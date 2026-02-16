package dice_test

import (
	"math/rand"
	"testing"

	. "github.com/xtls/xray-core/common/dice"
)

func TestRollBound(t *testing.T) {
	for i := 0; i < 1000; i++ {
		r := Roll(10)
		if r < 0 || r >= 10 {
			t.Fatalf("Roll(10) returned %d, want [0, 10)", r)
		}
	}
}

func TestRollOne(t *testing.T) {
	for i := 0; i < 100; i++ {
		if r := Roll(1); r != 0 {
			t.Fatalf("Roll(1) returned %d, want 0", r)
		}
	}
}

func TestRollInt63nBound(t *testing.T) {
	for i := 0; i < 1000; i++ {
		r := RollInt63n(100)
		if r < 0 || r >= 100 {
			t.Fatalf("RollInt63n(100) returned %d, want [0, 100)", r)
		}
	}
}

func TestRollInt63nOne(t *testing.T) {
	for i := 0; i < 100; i++ {
		if r := RollInt63n(1); r != 0 {
			t.Fatalf("RollInt63n(1) returned %d, want 0", r)
		}
	}
}

func TestRollDeterministic(t *testing.T) {
	r1 := RollDeterministic(1000, 42)
	r2 := RollDeterministic(1000, 42)
	if r1 != r2 {
		t.Fatalf("deterministic roll mismatch: %d != %d", r1, r2)
	}
}

func TestRollDeterministicOne(t *testing.T) {
	if r := RollDeterministic(1, 42); r != 0 {
		t.Fatalf("RollDeterministic(1, 42) returned %d, want 0", r)
	}
}

func TestRollUint16NotConstant(t *testing.T) {
	first := RollUint16()
	allSame := true
	for i := 0; i < 100; i++ {
		if RollUint16() != first {
			allSame = false
			break
		}
	}
	if allSame {
		t.Fatal("RollUint16 returned the same value 101 times in a row")
	}
}

func TestRollUint64NotConstant(t *testing.T) {
	first := RollUint64()
	allSame := true
	for i := 0; i < 100; i++ {
		if RollUint64() != first {
			allSame = false
			break
		}
	}
	if allSame {
		t.Fatal("RollUint64 returned the same value 101 times in a row")
	}
}

func TestNewDeterministicDice(t *testing.T) {
	dd := NewDeterministicDice(99)
	if dd == nil {
		t.Fatal("NewDeterministicDice returned nil")
	}
	if r := dd.Roll(1); r != 0 {
		t.Fatalf("DeterministicDice.Roll(1) returned %d, want 0", r)
	}
	dd1 := NewDeterministicDice(99)
	dd2 := NewDeterministicDice(99)
	for i := 0; i < 100; i++ {
		a := dd1.Roll(100)
		b := dd2.Roll(100)
		if a != b {
			t.Fatalf("deterministic dice diverged at step %d: %d != %d", i, a, b)
		}
	}
}

func BenchmarkRoll1(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Roll(1)
	}
}

func BenchmarkRoll20(b *testing.B) {
	for i := 0; i < b.N; i++ {
		Roll(20)
	}
}

func BenchmarkIntn1(b *testing.B) {
	for i := 0; i < b.N; i++ {
		rand.Intn(1)
	}
}

func BenchmarkIntn20(b *testing.B) {
	for i := 0; i < b.N; i++ {
		rand.Intn(20)
	}
}

func BenchmarkInt63(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = uint16(rand.Int63() >> 47)
	}
}

func BenchmarkInt31(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = uint16(rand.Int31() >> 15)
	}
}

func BenchmarkIntn(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = uint16(rand.Intn(65536))
	}
}
