package reality

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/xtls/reality"
	"github.com/xtls/xray-core/transport/internet"
	tls "github.com/xtls/xray-core/transport/internet/tls"
)

func (c *Config) GetREALITYConfig() *reality.Config {
	var dialer net.Dialer
	config := &reality.Config{
		DialContext: dialer.DialContext,

		Show: c.Show,
		Type: c.Type,
		Dest: c.Dest,
		Xver: byte(c.Xver),

		PrivateKey:   c.PrivateKey,
		MinClientVer: c.MinClientVer,
		MaxClientVer: c.MaxClientVer,
		MaxTimeDiff:  time.Duration(c.MaxTimeDiff) * time.Millisecond,

		NextProtos:             nil, // should be nil
		SessionTicketsDisabled: true,

		KeyLogWriter: KeyLogWriterFromConfig(c),
	}
	if c.Mldsa65Seed != nil {
		_, key := mldsa65.NewKeyFromSeed((*[32]byte)(c.Mldsa65Seed))
		config.Mldsa65Key = key.Bytes()
	}
	if c.LimitFallbackUpload != nil {
		config.LimitFallbackUpload.AfterBytes = c.LimitFallbackUpload.AfterBytes
		config.LimitFallbackUpload.BytesPerSec = c.LimitFallbackUpload.BytesPerSec
		config.LimitFallbackUpload.BurstBytesPerSec = c.LimitFallbackUpload.BurstBytesPerSec
	}
	if c.LimitFallbackDownload != nil {
		config.LimitFallbackDownload.AfterBytes = c.LimitFallbackDownload.AfterBytes
		config.LimitFallbackDownload.BytesPerSec = c.LimitFallbackDownload.BytesPerSec
		config.LimitFallbackDownload.BurstBytesPerSec = c.LimitFallbackDownload.BurstBytesPerSec
	}
	config.ServerNames = make(map[string]bool)
	for _, serverName := range c.ServerNames {
		config.ServerNames[serverName] = true
	}
	config.ShortIds = make(map[[8]byte]bool)
	for _, shortId := range c.ShortIds {
		config.ShortIds[*(*[8]byte)(shortId)] = true
	}
	return config
}

func KeyLogWriterFromConfig(c *Config) io.Writer {
	return tls.MasterKeyLogWriter(c.MasterKeyLog)
}

func ConfigFromStreamSettings(settings *internet.MemoryStreamConfig) *Config {
	if settings == nil {
		return nil
	}
	config, ok := settings.SecuritySettings.(*Config)
	if !ok {
		return nil
	}
	return config
}

// KeyPair holds an X25519 keypair for REALITY authentication.
type KeyPair struct {
	PrivateKey []byte
	PublicKey  []byte
	CreatedAt  time.Time
}

// KeyRotator manages periodic X25519 key rotation for the REALITY server.
// In-flight connections keep a reference to the key they started with.
type KeyRotator struct {
	mu       sync.RWMutex
	current  *KeyPair
	previous *KeyPair
	interval time.Duration
	grace    time.Duration
	stopCh   chan struct{}
}

// NewKeyRotator creates a KeyRotator starting with the given private key.
// If interval is 0, rotation is disabled and the initial key is used indefinitely.
func NewKeyRotator(initialPrivKey []byte, interval, grace time.Duration) *KeyRotator {
	if grace == 0 {
		grace = 5 * time.Minute
	}
	privKey, err := ecdh.X25519().NewPrivateKey(initialPrivKey)
	if err != nil {
		return nil
	}
	kr := &KeyRotator{
		current: &KeyPair{
			PrivateKey: append([]byte(nil), initialPrivKey...),
			PublicKey:  privKey.PublicKey().Bytes(),
			CreatedAt:  time.Now(),
		},
		interval: interval,
		grace:    grace,
		stopCh:   make(chan struct{}),
	}
	if interval > 0 {
		go kr.rotateLoop()
	}
	return kr
}

func (kr *KeyRotator) rotateLoop() {
	ticker := time.NewTicker(kr.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			kr.rotate()
		case <-kr.stopCh:
			return
		}
	}
}

func (kr *KeyRotator) rotate() {
	newPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return
	}
	kr.mu.Lock()
	rotatedOut := kr.current
	// Zero previous key material
	if kr.previous != nil {
		zeroBytes(kr.previous.PrivateKey)
	}
	kr.previous = rotatedOut
	kr.current = &KeyPair{
		PrivateKey: newPriv.Bytes(),
		PublicKey:  newPriv.PublicKey().Bytes(),
		CreatedAt:  time.Now(),
	}
	kr.mu.Unlock()

	// After grace period, clear only the specific key rotated out in this call.
	time.AfterFunc(kr.grace, func() {
		kr.mu.Lock()
		if kr.previous == rotatedOut {
			zeroBytes(rotatedOut.PrivateKey)
			kr.previous = nil
		}
		kr.mu.Unlock()
	})
}

// CurrentKey returns the active keypair.
func (kr *KeyRotator) CurrentKey() *KeyPair {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	return kr.current
}

// TryAuth attempts ECDH auth using the key identified by serverPubKeyBytes when provided.
// Without an explicit key, it prefers the current key, then falls back to the previous
// key during grace period.
// Returns the shared secret and true if authentication succeeded.
func (kr *KeyRotator) TryAuth(clientPubKeyBytes []byte, serverPubKeyBytes ...[]byte) ([]byte, bool) {
	kr.mu.RLock()
	defer kr.mu.RUnlock()

	clientPub, err := ecdh.X25519().NewPublicKey(clientPubKeyBytes)
	if err != nil {
		return nil, false
	}

	tryPair := func(pair *KeyPair) ([]byte, bool) {
		if pair == nil {
			return nil, false
		}
		privKey, err := ecdh.X25519().NewPrivateKey(pair.PrivateKey)
		if err != nil {
			return nil, false
		}
		shared, err := privKey.ECDH(clientPub)
		if err != nil {
			return nil, false
		}
		return shared, true
	}

	var serverPub []byte
	if len(serverPubKeyBytes) > 0 {
		serverPub = serverPubKeyBytes[0]
	}

	if len(serverPub) > 0 {
		if kr.current != nil && bytes.Equal(serverPub, kr.current.PublicKey) {
			return tryPair(kr.current)
		}
		if kr.previous != nil && bytes.Equal(serverPub, kr.previous.PublicKey) {
			return tryPair(kr.previous)
		}
		return nil, false
	}

	if shared, ok := tryPair(kr.current); ok {
		return shared, true
	}
	if shared, ok := tryPair(kr.previous); ok {
		return shared, true
	}

	return nil, false
}

// PrivateKey returns the current private key bytes (for compatibility with existing config flow).
func (kr *KeyRotator) PrivateKey() []byte {
	kr.mu.RLock()
	defer kr.mu.RUnlock()
	if kr.current != nil {
		return kr.current.PrivateKey
	}
	return nil
}

// Stop stops the rotation goroutine and zeroes all key material.
func (kr *KeyRotator) Stop() {
	close(kr.stopCh)
	kr.mu.Lock()
	defer kr.mu.Unlock()
	if kr.current != nil {
		zeroBytes(kr.current.PrivateKey)
	}
	if kr.previous != nil {
		zeroBytes(kr.previous.PrivateKey)
	}
}

// zeroBytes overwrites b with zeroes.
//
//go:noinline
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
