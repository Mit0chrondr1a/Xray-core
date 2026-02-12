package http

import (
	"crypto/sha256"
	"crypto/subtle"

	"google.golang.org/protobuf/proto"

	"github.com/xtls/xray-core/common/protocol"
)

func (a *Account) Equals(another protocol.Account) bool {
	if account, ok := another.(*Account); ok {
		return a.Username == account.Username
	}
	return false
}

func (a *Account) ToProto() proto.Message {
	return a
}

func (a *Account) AsAccount() (protocol.Account, error) {
	return a, nil
}

func (sc *ServerConfig) HasAccount(username, password string) bool {
	if sc.Accounts == nil {
		return false
	}

	p, found := sc.Accounts[username]
	if !found {
		p = password // dummy: prevent username enumeration timing
	}

	// Hash both to fixed-length to prevent length-based timing leaks.
	// subtle.ConstantTimeCompare returns 0 immediately for different-length
	// inputs, so raw comparison would leak stored password length.
	storedHash := sha256.Sum256([]byte(p))
	inputHash := sha256.Sum256([]byte(password))

	passwordMatch := subtle.ConstantTimeCompare(storedHash[:], inputHash[:]) == 1
	return passwordMatch && found
}
