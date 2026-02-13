//go:build linux

package tls

import (
	"crypto"
	"crypto/hkdf"
	gotls "crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	TLS_SET_RECORD_TYPE = 1
	TLS_GET_RECORD_TYPE = 2

	recordTypeHandshake byte = 22
	typeKeyUpdate       byte = 24
)

// KTLSKeyUpdateHandler handles TLS 1.3 KeyUpdate messages for kTLS connections.
// When the kernel encounters a KeyUpdate record it cannot process, it returns
// EKEYEXPIRED on subsequent reads. This handler derives new traffic keys via
// HKDF-Expand-Label (RFC 8446 Section 7.2) and reinstalls them via setsockopt.
type KTLSKeyUpdateHandler struct {
	mu            sync.Mutex
	fd            int
	cipherSuiteID uint16
	hashFunc      crypto.Hash
	keyLen        int
	rxSecret      []byte
	txSecret      []byte
}

func newKTLSKeyUpdateHandler(fd int, cipherSuiteID uint16, rxSecret, txSecret []byte) *KTLSKeyUpdateHandler {
	var hashFunc crypto.Hash
	var keyLen int
	switch cipherSuiteID {
	case gotls.TLS_AES_128_GCM_SHA256:
		hashFunc = crypto.SHA256
		keyLen = 16
	case gotls.TLS_AES_256_GCM_SHA384:
		hashFunc = crypto.SHA384
		keyLen = 32
	case gotls.TLS_CHACHA20_POLY1305_SHA256:
		hashFunc = crypto.SHA256
		keyLen = 32
	default:
		return nil
	}
	return &KTLSKeyUpdateHandler{
		fd:            fd,
		cipherSuiteID: cipherSuiteID,
		hashFunc:      hashFunc,
		keyLen:        keyLen,
		rxSecret:      append([]byte(nil), rxSecret...),
		txSecret:      append([]byte(nil), txSecret...),
	}
}

// Handle processes a pending TLS 1.3 KeyUpdate after the kernel returns EKEYEXPIRED.
func (h *KTLSKeyUpdateHandler) Handle() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Read the decrypted KeyUpdate message from the kernel's control record queue.
	recordType, data, err := recvControlRecord(h.fd)
	if err != nil {
		return fmt.Errorf("ktls: recvControlRecord: %w", err)
	}
	if recordType != recordTypeHandshake {
		return fmt.Errorf("ktls: expected handshake record type %d, got %d", recordTypeHandshake, recordType)
	}

	// Parse: handshake_type(1) + length(3) + update_requested(1) = 5 bytes
	if len(data) < 5 || data[0] != typeKeyUpdate {
		return fmt.Errorf("ktls: invalid KeyUpdate: len=%d", len(data))
	}
	msgLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if msgLen != 1 {
		return fmt.Errorf("ktls: unexpected KeyUpdate body length: %d", msgLen)
	}
	updateRequested := data[4]

	hashSize := h.hashFunc.Size()

	// Derive new RX traffic secret and key material (RFC 8446 Section 7.2).
	newRxSecret := expandLabel(h.hashFunc, h.rxSecret, "traffic upd", nil, hashSize)
	newRxKey := expandLabel(h.hashFunc, newRxSecret, "key", nil, h.keyLen)
	newRxIV := expandLabel(h.hashFunc, newRxSecret, "iv", nil, 12)

	// Install new RX key with reset sequence number.
	if err := setKTLSCryptoInfo(h.fd, TLS_RX, TLS_1_3_VERSION, h.cipherSuiteID, newRxKey, newRxIV, make([]byte, 8)); err != nil {
		return fmt.Errorf("ktls: setsockopt TLS_RX: %w", err)
	}
	h.rxSecret = newRxSecret

	// If the peer requested a key update, respond and rotate TX keys.
	if updateRequested == 1 {
		kuResponse := []byte{typeKeyUpdate, 0, 0, 1, 0}
		if err := sendControlRecord(h.fd, recordTypeHandshake, kuResponse); err != nil {
			return fmt.Errorf("ktls: sendmsg KeyUpdate response: %w", err)
		}

		newTxSecret := expandLabel(h.hashFunc, h.txSecret, "traffic upd", nil, hashSize)
		newTxKey := expandLabel(h.hashFunc, newTxSecret, "key", nil, h.keyLen)
		newTxIV := expandLabel(h.hashFunc, newTxSecret, "iv", nil, 12)

		if err := setKTLSCryptoInfo(h.fd, TLS_TX, TLS_1_3_VERSION, h.cipherSuiteID, newTxKey, newTxIV, make([]byte, 8)); err != nil {
			return fmt.Errorf("ktls: setsockopt TLS_TX: %w", err)
		}
		h.txSecret = newTxSecret
	}

	return nil
}

// expandLabel implements HKDF-Expand-Label from RFC 8446 Section 7.1.
func expandLabel(hashFunc crypto.Hash, secret []byte, label string, context []byte, length int) []byte {
	hkdfLabel := make([]byte, 0, 2+1+6+len(label)+1+len(context))
	hkdfLabel = binary.BigEndian.AppendUint16(hkdfLabel, uint16(length))
	hkdfLabel = append(hkdfLabel, byte(6+len(label)))
	hkdfLabel = append(hkdfLabel, "tls13 "...)
	hkdfLabel = append(hkdfLabel, label...)
	hkdfLabel = append(hkdfLabel, byte(len(context)))
	hkdfLabel = append(hkdfLabel, context...)
	out, _ := hkdf.Expand(hashFunc.New, secret, string(hkdfLabel), length)
	return out
}

// recvControlRecord reads a TLS control record from the kernel via recvmsg.
// The kernel queues the decrypted record and annotates it with TLS_GET_RECORD_TYPE in cmsg.
func recvControlRecord(fd int) (recordType byte, data []byte, err error) {
	dataBuf := make([]byte, 256)
	oob := make([]byte, syscall.CmsgSpace(1))

	n, oobn, _, _, err := syscall.Recvmsg(fd, dataBuf, oob, 0)
	if err != nil {
		return 0, nil, fmt.Errorf("recvmsg: %w", err)
	}

	cmsgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return 0, nil, fmt.Errorf("parse cmsg: %w", err)
	}
	for _, cmsg := range cmsgs {
		if cmsg.Header.Level == SOL_TLS && cmsg.Header.Type == TLS_GET_RECORD_TYPE {
			if len(cmsg.Data) >= 1 {
				recordType = cmsg.Data[0]
			}
		}
	}
	if recordType == 0 {
		return 0, nil, fmt.Errorf("no TLS_GET_RECORD_TYPE cmsg")
	}

	return recordType, dataBuf[:n], nil
}

// sendControlRecord sends a TLS control record via sendmsg with TLS_SET_RECORD_TYPE cmsg.
func sendControlRecord(fd int, recordType byte, data []byte) error {
	oob := make([]byte, syscall.CmsgSpace(1))
	cmsg := (*syscall.Cmsghdr)(unsafe.Pointer(&oob[0]))
	cmsg.Level = SOL_TLS
	cmsg.Type = TLS_SET_RECORD_TYPE
	cmsg.SetLen(syscall.CmsgLen(1))
	oob[syscall.CmsgLen(0)] = recordType

	return syscall.Sendmsg(fd, data, oob, nil, 0)
}

// IsKeyExpired checks if an error indicates the kernel's kTLS keys have expired
// due to a TLS 1.3 KeyUpdate.
func IsKeyExpired(err error) bool {
	return isKeyExpired(err)
}

func isKeyExpired(err error) bool {
	return errors.Is(err, unix.EKEYEXPIRED)
}
