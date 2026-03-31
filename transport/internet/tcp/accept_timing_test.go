package tcp

import (
	"net"
	"testing"
)

func TestTakeAcceptStartUnixNanoConsumesStoredTimestamp(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()

	const want int64 = 123456789
	recordAcceptStartUnixNano(left, want)

	if got := TakeAcceptStartUnixNano(left); got != want {
		t.Fatalf("TakeAcceptStartUnixNano() = %d, want %d", got, want)
	}
	if got := TakeAcceptStartUnixNano(left); got != 0 {
		t.Fatalf("TakeAcceptStartUnixNano() second read = %d, want 0", got)
	}
}
