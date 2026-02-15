package salamander

import (
	crand "crypto/rand"
	"fmt"
	"math/rand/v2"

	"golang.org/x/crypto/blake2b"
)

const (
	smPSKMinLen = 4
	smSaltLen   = 8
	smKeyLen    = blake2b.Size256
)

var ErrPSKTooShort = fmt.Errorf("PSK must be at least %d bytes", smPSKMinLen)

// SalamanderObfuscator is an obfuscator that obfuscates each packet with
// the BLAKE2b-256 hash of a pre-shared key combined with a random salt.
// Packet format: [8-byte salt][payload]

// newCSPRNG returns a ChaCha8-based userspace PRNG seeded from crypto/rand.
// This avoids a getrandom(2) syscall per packet while remaining unpredictable.
func newCSPRNG() *rand.ChaCha8 {
	var seed [32]byte
	if _, err := crand.Read(seed[:]); err != nil {
		panic("salamander: failed to seed CSPRNG: " + err.Error())
	}
	return rand.NewChaCha8(seed)
}

type SalamanderObfuscator struct {
	PSK []byte
	rng *rand.ChaCha8
}

func NewSalamanderObfuscator(psk []byte) (*SalamanderObfuscator, error) {
	if len(psk) < smPSKMinLen {
		return nil, ErrPSKTooShort
	}
	return &SalamanderObfuscator{
		PSK: psk,
		rng: newCSPRNG(),
	}, nil
}

func (o *SalamanderObfuscator) Obfuscate(in, out []byte) int {
	outLen := len(in) + smSaltLen
	if len(out) < outLen {
		return 0
	}
	// ChaCha8 Read never returns an error
	o.rng.Read(out[:smSaltLen])
	key := o.key(out[:smSaltLen])
	for i, c := range in {
		out[i+smSaltLen] = c ^ key[i%smKeyLen]
	}
	return outLen
}

func (o *SalamanderObfuscator) Deobfuscate(in, out []byte) int {
	outLen := len(in) - smSaltLen
	if outLen <= 0 || len(out) < outLen {
		return 0
	}
	key := o.key(in[:smSaltLen])
	for i, c := range in[smSaltLen:] {
		out[i] = c ^ key[i%smKeyLen]
	}
	return outLen
}

func (o *SalamanderObfuscator) key(salt []byte) [smKeyLen]byte {
	return blake2b.Sum256(append(o.PSK, salt...))
}
