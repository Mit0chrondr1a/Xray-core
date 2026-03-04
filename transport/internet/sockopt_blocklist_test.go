package internet

import "testing"

// Test constants matching sockopt_blocklist.go
const (
	testSolSocketLinux = 1
	testSolSocketBSD   = 0xFFFF
	testSolTCP         = 6
	testSoAttachBPF    = 50
	testSoAttachFilter = 26
	testSoAttachReuse  = 52
	testTCPRepair      = 19
)

func TestIsBlockedSockopt_LinuxBPF(t *testing.T) {
	if !isBlockedSockopt(testSolSocketLinux, testSoAttachBPF) {
		t.Fatal("SO_ATTACH_BPF (Linux SOL_SOCKET=1, 50) must be blocked")
	}
}

func TestIsBlockedSockopt_BsdBPF(t *testing.T) {
	if !isBlockedSockopt(testSolSocketBSD, testSoAttachBPF) {
		t.Fatal("SO_ATTACH_BPF (BSD SOL_SOCKET=0xFFFF, 50) must be blocked")
	}
}

func TestIsBlockedSockopt_AttachFilter(t *testing.T) {
	if !isBlockedSockopt(testSolSocketLinux, testSoAttachFilter) {
		t.Fatal("SO_ATTACH_FILTER (Linux, 26) must be blocked")
	}
	if !isBlockedSockopt(testSolSocketBSD, testSoAttachFilter) {
		t.Fatal("SO_ATTACH_FILTER (BSD, 26) must be blocked")
	}
}

func TestIsBlockedSockopt_ReuseportBPF(t *testing.T) {
	if !isBlockedSockopt(testSolSocketLinux, testSoAttachReuse) {
		t.Fatal("SO_ATTACH_REUSEPORT_EBPF (Linux, 52) must be blocked")
	}
}

func TestIsBlockedSockopt_TCPRepair(t *testing.T) {
	if !isBlockedSockopt(testSolTCP, testTCPRepair) {
		t.Fatal("TCP_REPAIR (SOL_TCP=6, 19) must be blocked")
	}
}

func TestIsBlockedSockopt_AllowsLegitimate(t *testing.T) {
	tests := []struct {
		name  string
		level int
		opt   int
	}{
		{"SOL_SOCKET/SO_REUSEADDR(Linux)", testSolSocketLinux, 2},
		{"SOL_SOCKET/SO_KEEPALIVE(Linux)", testSolSocketLinux, 9},
		{"SOL_TCP/TCP_NODELAY", testSolTCP, 1},
		{"IPPROTO_IP/IP_TOS", 0, 1},
		{"SOL_SOCKET/SO_KEEPALIVE(BSD)", testSolSocketBSD, 8},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if isBlockedSockopt(tt.level, tt.opt) {
				t.Fatalf("legitimate sockopt level=%d opt=%d should not be blocked", tt.level, tt.opt)
			}
		})
	}
}

func TestIsBlockedSockopt_WrongLevel(t *testing.T) {
	// BPF opts on wrong level should pass
	if isBlockedSockopt(testSolTCP, testSoAttachBPF) {
		t.Fatal("SO_ATTACH_BPF on SOL_TCP should not be blocked")
	}
	// TCP_REPAIR on wrong level should pass
	if isBlockedSockopt(testSolSocketLinux, testTCPRepair) {
		t.Fatal("TCP_REPAIR on SOL_SOCKET should not be blocked")
	}
}

func TestIsBlockedSockopt_ZeroValues(t *testing.T) {
	if isBlockedSockopt(0, 0) {
		t.Fatal("(0, 0) should not be blocked")
	}
}

func TestValidateCustomSockopt_Blocked(t *testing.T) {
	err := validateCustomSockopt(testSolSocketLinux, testSoAttachBPF)
	if err == nil {
		t.Fatal("validateCustomSockopt should return error for blocked option")
	}
}

func TestValidateCustomSockopt_Allowed(t *testing.T) {
	err := validateCustomSockopt(testSolTCP, 1) // TCP_NODELAY
	if err != nil {
		t.Fatalf("validateCustomSockopt should allow legitimate option: %v", err)
	}
}
