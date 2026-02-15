// Package dice contains common functions to generate random number.
package dice // import "github.com/xtls/xray-core/common/dice"

import (
	"math/rand/v2"
)

// Roll returns a non-negative number between 0 (inclusive) and n (exclusive).
func Roll(n int) int {
	if n == 1 {
		return 0
	}
	return rand.IntN(n)
}

// RollInt63n returns a non-negative number between 0 (inclusive) and n (exclusive).
func RollInt63n(n int64) int64 {
	if n == 1 {
		return 0
	}
	return rand.Int64N(n)
}

// RollDeterministic returns a non-negative number between 0 (inclusive) and n (exclusive).
func RollDeterministic(n int, seed int64) int {
	if n == 1 {
		return 0
	}
	return rand.New(rand.NewPCG(0, uint64(seed))).IntN(n)
}

// RollUint16 returns a random uint16 value.
func RollUint16() uint16 {
	return uint16(rand.Int64() >> 47)
}

func RollUint64() uint64 {
	return rand.Uint64()
}

func NewDeterministicDice(seed int64) *DeterministicDice {
	return &DeterministicDice{rand.New(rand.NewPCG(0, uint64(seed)))}
}

type DeterministicDice struct {
	*rand.Rand
}

func (dd *DeterministicDice) Roll(n int) int {
	if n == 1 {
		return 0
	}
	return dd.IntN(n)
}
