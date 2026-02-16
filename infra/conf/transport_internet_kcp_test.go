package conf_test

import (
	"testing"

	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/internet/kcp"
)

func uint32Ptr(v uint32) *uint32 { return &v }

func TestKCPConfig_Build_ReadBufferSize_ClampedAt2048(t *testing.T) {
	tests := []struct {
		name     string
		size     uint32
		wantSize uint32 // in bytes (after * 1024 * 1024)
	}{
		{
			name:     "normal value 16 is not clamped",
			size:     16,
			wantSize: 16 * 1024 * 1024,
		},
		{
			name:     "exactly 2048 is accepted",
			size:     2048,
			wantSize: 2048 * 1024 * 1024,
		},
		{
			name:     "2049 is clamped to 2048",
			size:     2049,
			wantSize: 2048 * 1024 * 1024,
		},
		{
			name:     "max uint32 is clamped to 2048",
			size:     4294967295,
			wantSize: 2048 * 1024 * 1024,
		},
		{
			name:     "zero gets default 512KB",
			size:     0,
			wantSize: 512 * 1024,
		},
		{
			name:     "1 is 1MB",
			size:     1,
			wantSize: 1 * 1024 * 1024,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &KCPConfig{
				ReadBufferSize: uint32Ptr(tt.size),
			}
			msg, err := cfg.Build()
			if err != nil {
				t.Fatalf("Build() returned error: %v", err)
			}
			kcpCfg := msg.(*kcp.Config)
			if kcpCfg.ReadBuffer == nil {
				t.Fatal("ReadBuffer is nil, expected non-nil")
			}
			if kcpCfg.ReadBuffer.Size != tt.wantSize {
				t.Errorf("ReadBuffer.Size = %d, want %d", kcpCfg.ReadBuffer.Size, tt.wantSize)
			}
		})
	}
}

func TestKCPConfig_Build_WriteBufferSize_ClampedAt2048(t *testing.T) {
	tests := []struct {
		name     string
		size     uint32
		wantSize uint32
	}{
		{
			name:     "normal value 32 is not clamped",
			size:     32,
			wantSize: 32 * 1024 * 1024,
		},
		{
			name:     "exactly 2048 is accepted",
			size:     2048,
			wantSize: 2048 * 1024 * 1024,
		},
		{
			name:     "2049 is clamped to 2048",
			size:     2049,
			wantSize: 2048 * 1024 * 1024,
		},
		{
			name:     "max uint32 is clamped to 2048",
			size:     4294967295,
			wantSize: 2048 * 1024 * 1024,
		},
		{
			name:     "zero gets default 512KB",
			size:     0,
			wantSize: 512 * 1024,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &KCPConfig{
				WriteBufferSize: uint32Ptr(tt.size),
			}
			msg, err := cfg.Build()
			if err != nil {
				t.Fatalf("Build() returned error: %v", err)
			}
			kcpCfg := msg.(*kcp.Config)
			if kcpCfg.WriteBuffer == nil {
				t.Fatal("WriteBuffer is nil, expected non-nil")
			}
			if kcpCfg.WriteBuffer.Size != tt.wantSize {
				t.Errorf("WriteBuffer.Size = %d, want %d", kcpCfg.WriteBuffer.Size, tt.wantSize)
			}
		})
	}
}

func TestKCPConfig_Build_NilBufferSizes(t *testing.T) {
	cfg := &KCPConfig{}
	msg, err := cfg.Build()
	if err != nil {
		t.Fatalf("Build() returned error: %v", err)
	}
	kcpCfg := msg.(*kcp.Config)
	if kcpCfg.ReadBuffer != nil {
		t.Errorf("ReadBuffer should be nil when not configured, got %+v", kcpCfg.ReadBuffer)
	}
	if kcpCfg.WriteBuffer != nil {
		t.Errorf("WriteBuffer should be nil when not configured, got %+v", kcpCfg.WriteBuffer)
	}
}

func TestKCPConfig_Build_BothBuffersClampedSimultaneously(t *testing.T) {
	readSize := uint32(5000)
	writeSize := uint32(9999)
	cfg := &KCPConfig{
		ReadBufferSize:  &readSize,
		WriteBufferSize: &writeSize,
	}
	msg, err := cfg.Build()
	if err != nil {
		t.Fatalf("Build() returned error: %v", err)
	}
	kcpCfg := msg.(*kcp.Config)
	wantBytes := uint32(2048 * 1024 * 1024)
	if kcpCfg.ReadBuffer.Size != wantBytes {
		t.Errorf("ReadBuffer.Size = %d, want %d (clamped)", kcpCfg.ReadBuffer.Size, wantBytes)
	}
	if kcpCfg.WriteBuffer.Size != wantBytes {
		t.Errorf("WriteBuffer.Size = %d, want %d (clamped)", kcpCfg.WriteBuffer.Size, wantBytes)
	}
}
