package inbound

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
	"unsafe"
)

type visionLayoutOK struct {
	prefix   byte
	rawInput bytes.Buffer
	input    bytes.Reader
}

type visionLayoutMissing struct {
	input bytes.Reader
}

type visionLayoutWrongTypes struct {
	rawInput bytes.Reader
	input    bytes.Buffer
}

func TestResolveVisionInternalReadersAcceptsExpectedLayout(t *testing.T) {
	state := &visionLayoutOK{prefix: 7}
	state.rawInput.WriteString("raw")
	state.input.Reset([]byte("hello"))

	input, rawInput, err := resolveVisionInternalReaders(reflect.TypeOf(*state), uintptr(unsafe.Pointer(state)))
	if err != nil {
		t.Fatalf("resolveVisionInternalReaders() error = %v", err)
	}
	if input == nil || rawInput == nil {
		t.Fatal("resolveVisionInternalReaders() returned nil pointers for valid layout")
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
	state := &visionLayoutMissing{}
	_, _, err := resolveVisionInternalReaders(reflect.TypeOf(*state), uintptr(unsafe.Pointer(state)))
	if err == nil {
		t.Fatal("resolveVisionInternalReaders() error = nil, want missing-field error")
	}
	if !strings.Contains(err.Error(), "missing input/rawInput fields") {
		t.Fatalf("error = %q, want missing-field message", err.Error())
	}
}

func TestResolveVisionInternalReadersRejectsWrongFieldTypes(t *testing.T) {
	state := &visionLayoutWrongTypes{}
	_, _, err := resolveVisionInternalReaders(reflect.TypeOf(*state), uintptr(unsafe.Pointer(state)))
	if err == nil {
		t.Fatal("resolveVisionInternalReaders() error = nil, want wrong-type error")
	}
	if !strings.Contains(err.Error(), "unexpected input/rawInput types") {
		t.Fatalf("error = %q, want wrong-type message", err.Error())
	}
}
