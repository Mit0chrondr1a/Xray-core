package outbound

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
	"unsafe"
)

type outboundVisionLayoutOK struct {
	prefix   byte
	rawInput bytes.Buffer
	input    bytes.Reader
}

type outboundVisionLayoutMissing struct {
	input bytes.Reader
}

type outboundVisionLayoutWrongTypes struct {
	rawInput bytes.Reader
	input    bytes.Buffer
}

func TestResolveVisionInternalReadersAcceptsExpectedLayout(t *testing.T) {
	state := &outboundVisionLayoutOK{prefix: 7}
	state.rawInput.WriteString("raw")
	state.input.Reset([]byte("hello"))

	input, rawInput, err := resolveVisionInternalReaders(reflect.TypeOf(*state), unsafe.Pointer(state))
	if err != nil {
		t.Fatalf("resolveVisionInternalReaders() error = %v", err)
	}
	buf := make([]byte, 5)
	if n, readErr := input.Read(buf); readErr != nil || n != 5 || string(buf[:n]) != "hello" {
		t.Fatalf("input reader = (%d, %v, %q), want (5, nil, %q)", n, readErr, string(buf[:n]), "hello")
	}
	if got := rawInput.String(); got != "raw" {
		t.Fatalf("rawInput.String() = %q, want %q", got, "raw")
	}
}

func TestResolveVisionInternalReadersRejectsMissingFields(t *testing.T) {
	state := &outboundVisionLayoutMissing{}
	_, _, err := resolveVisionInternalReaders(reflect.TypeOf(*state), unsafe.Pointer(state))
	if err == nil || !strings.Contains(err.Error(), "missing input/rawInput fields") {
		t.Fatalf("error = %v, want missing-field error", err)
	}
}

func TestResolveVisionInternalReadersRejectsWrongFieldTypes(t *testing.T) {
	state := &outboundVisionLayoutWrongTypes{}
	_, _, err := resolveVisionInternalReaders(reflect.TypeOf(*state), unsafe.Pointer(state))
	if err == nil || !strings.Contains(err.Error(), "unexpected input/rawInput types") {
		t.Fatalf("error = %v, want wrong-type error", err)
	}
}
