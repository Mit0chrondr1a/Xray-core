//go:build linux

package ebpf

import (
	"bufio"
	"compress/gzip"
	"context"
	"os"
	"strconv"
	"strings"
	"syscall"

	xerrors "github.com/xtls/xray-core/common/errors"
	xlog "github.com/xtls/xray-core/common/log"
	"golang.org/x/sys/unix"
)

// logAccelerationSummary emits a single-line startup summary of which
// acceleration paths are available for each connection type.
func logAccelerationSummary(ctx context.Context) {
	ktlsCompat := KTLSSockhashCompatible()
	ktlsPath := "sockmap"
	ktlsDetail := "probe-passed"
	if !ktlsCompat {
		ktlsPath = "splice"
		ktlsDetail = "probe-failed"
	}

	st := currentState.Load()
	sockhashFD := -1
	if st != nil {
		sockhashFD = st.sockhashFD
	}

	// Determine loader type and resolve sockhash FD for display.
	loaderType := "go-native"
	if nativeEbpfAvailable() && st != nil && st.sockmapPinPath != "" && sockhashFD < 0 {
		// Rust/Aya loader is active — FDs are Rust-managed, so sockhashFD is -1.
		loaderType = "rust-aya"
		// Try to open pinned sockhash for FD display (best-effort).
		if fd, err := openPinnedBPFMap(sockhashPinPath(st.sockmapPinPath)); err == nil {
			sockhashFD = fd
			defer syscall.Close(fd)
		}
	}

	capacity := DefaultSockmapConfig().MaxEntries

	xerrors.LogInfo(ctx,
		"sockmap: acceleration summary — loader=", loaderType,
		" plain-TCP=sockmap kTLS=", ktlsPath,
		"(", ktlsDetail, ") kernel=", unameRelease(),
		" sockhash-fd=", sockhashFD,
		" capacity=", capacity,
	)
}

// logSockmapDeploymentDebug emits debug-only deployment diagnostics to help
// explain why sockmap init/prog load failed on production VPS/container setups.
func logSockmapDeploymentDebug(ctx context.Context, caps Capabilities, initErr error) {
	// Avoid procfs/kernel-config probing when debug logs are not emitted.
	if !xlog.IsSeverityEnabled(xlog.Severity_Debug) {
		return
	}

	xerrors.LogDebug(ctx,
		"eBPF debug caps: kernel=", caps.KernelVersion.String(),
		" sockmap=", caps.SockmapSupported,
		" sk_skb=", caps.SockmapSKSkbSupported,
		" xdp=", caps.XDPSupported,
		" btf=", caps.BTFSupported,
		" kTLS+SOCKHASH=", KTLSSockhashCompatible(),
	)

	if initErr != nil {
		xerrors.LogDebug(ctx, "eBPF debug trigger: sockmap manager init failed")
	} else {
		xerrors.LogDebug(ctx, "eBPF debug trigger: sockmap capability gate")
		// Capability-gated disable is expected on unsupported kernels. Avoid
		// expensive /proc and /boot probing in this path.
		return
	}

	inContainer, containerHints := detectContainerHints()
	selfCgroup := readFileSummary("/proc/self/cgroup", 256)
	initCgroup := readFileSummary("/proc/1/cgroup", 256)
	pid1Comm := readFirstLineOrUnknown("/proc/1/comm")
	selfNetns := readLinkOrUnknown("/proc/self/ns/net")
	initNetns := readLinkOrUnknown("/proc/1/ns/net")

	xerrors.LogDebug(ctx,
		"eBPF debug deploy: inContainer=", inContainer,
		" hints=", strings.Join(containerHints, ","),
		" pid1=", pid1Comm,
		" selfNetns=", selfNetns,
		" pid1Netns=", initNetns,
		" selfCgroup=", selfCgroup,
		" pid1Cgroup=", initCgroup,
	)

	capEff, capBnd, seccomp, noNewPrivs := readProcStatusSecurityFields("/proc/self/status")
	memlock := getMemlockLimit()
	unprivBPF := readFirstLineOrUnknown("/proc/sys/kernel/unprivileged_bpf_disabled")
	jitEnable := readFirstLineOrUnknown("/proc/sys/net/core/bpf_jit_enable")
	jitHarden := readFirstLineOrUnknown("/proc/sys/net/core/bpf_jit_harden")

	xerrors.LogDebug(ctx,
		"eBPF debug security: CapEff=", capEff,
		" CapBnd=", capBnd,
		" Seccomp=", seccomp,
		" NoNewPrivs=", noNewPrivs,
		" memlock=", memlock,
		" unprivileged_bpf_disabled=", unprivBPF,
		" bpf_jit_enable=", jitEnable,
		" bpf_jit_harden=", jitHarden,
	)

	bpffsMounted, bpffsType, bpffsOpts := probeMountPoint("/proc/self/mountinfo", "/sys/fs/bpf")
	xerrors.LogDebug(ctx,
		"eBPF debug fs: bpffsMounted=", bpffsMounted,
		" fsType=", bpffsType,
		" mountOpts=", bpffsOpts,
	)

	bpfSyscall := detectKernelConfigOption("CONFIG_BPF_SYSCALL")
	bpfJit := detectKernelConfigOption("CONFIG_BPF_JIT")
	streamParser := detectKernelConfigOption("CONFIG_BPF_STREAM_PARSER")
	xerrors.LogDebug(ctx,
		"eBPF debug kernel-config: CONFIG_BPF_SYSCALL=", bpfSyscall,
		" CONFIG_BPF_JIT=", bpfJit,
		" CONFIG_BPF_STREAM_PARSER=", streamParser,
	)
}

func detectContainerHints() (bool, []string) {
	hints := make([]string, 0, 8)
	addHint := func(v string) {
		if v == "" {
			return
		}
		for _, cur := range hints {
			if cur == v {
				return
			}
		}
		hints = append(hints, v)
	}

	if _, err := os.Stat("/.dockerenv"); err == nil {
		addHint("/.dockerenv")
	}
	if _, err := os.Stat("/run/.containerenv"); err == nil {
		addHint("/run/.containerenv")
	}
	if c := strings.TrimSpace(os.Getenv("container")); c != "" {
		addHint("env:container=" + c)
	}
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		addHint("env:kubernetes")
	}

	runtimeTokens := []string{
		"docker",
		"containerd",
		"kubepods",
		"cri-containerd",
		"crio",
		"libpod",
		"lxc",
	}

	for _, path := range []string{"/proc/self/cgroup", "/proc/1/cgroup"} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		content := strings.ToLower(string(data))
		for _, tok := range runtimeTokens {
			if strings.Contains(content, tok) {
				addHint(path + ":" + tok)
			}
		}
	}

	return len(hints) > 0, hints
}

func readFirstLineOrUnknown(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return "unknown"
	}
	text := strings.TrimSpace(string(data))
	if text == "" {
		return "unknown"
	}
	if i := strings.IndexByte(text, '\n'); i >= 0 {
		text = text[:i]
	}
	return strings.TrimSpace(text)
}

func readFileSummary(path string, limit int) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return "unknown"
	}
	text := strings.TrimSpace(string(data))
	if text == "" {
		return "empty"
	}
	text = strings.ReplaceAll(text, "\n", ";")
	if limit > 0 && len(text) > limit {
		return text[:limit] + "..."
	}
	return text
}

func readLinkOrUnknown(path string) string {
	target, err := os.Readlink(path)
	if err != nil {
		return "unknown"
	}
	if target == "" {
		return "unknown"
	}
	return target
}

func readProcStatusSecurityFields(path string) (capEff, capBnd, seccomp, noNewPrivs string) {
	capEff, capBnd, seccomp, noNewPrivs = "unknown", "unknown", "unknown", "unknown"

	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "CapEff:"):
			capEff = strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
		case strings.HasPrefix(line, "CapBnd:"):
			capBnd = strings.TrimSpace(strings.TrimPrefix(line, "CapBnd:"))
		case strings.HasPrefix(line, "Seccomp:"):
			seccomp = strings.TrimSpace(strings.TrimPrefix(line, "Seccomp:"))
		case strings.HasPrefix(line, "NoNewPrivs:"):
			noNewPrivs = strings.TrimSpace(strings.TrimPrefix(line, "NoNewPrivs:"))
		}
	}

	return
}

func getMemlockLimit() string {
	var rlim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &rlim); err != nil {
		return "unknown"
	}
	const rlimInfinity = ^uint64(0)
	if rlim.Cur == rlimInfinity {
		return "unlimited"
	}
	return strconv.FormatUint(rlim.Cur, 10)
}

func probeMountPoint(mountInfoPath, mountPoint string) (mounted bool, fsType, mountOpts string) {
	f, err := os.Open(mountInfoPath)
	if err != nil {
		return false, "unknown", "unknown"
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		if fields[4] != mountPoint {
			continue
		}
		sep := -1
		for i, v := range fields {
			if v == "-" {
				sep = i
				break
			}
		}
		if sep == -1 || sep+3 >= len(fields) {
			return true, "unknown", fields[5]
		}
		return true, fields[sep+1], fields[5] + ";" + fields[sep+3]
	}

	return false, "none", "none"
}

func detectKernelConfigOption(option string) string {
	if option == "" {
		return "unknown"
	}

	var paths []string
	if rel := readFirstLineOrUnknown("/proc/sys/kernel/osrelease"); rel != "unknown" {
		paths = append(paths, "/boot/config-"+rel)
	}
	paths = append(paths, "/boot/config", "/proc/config.gz")

	for _, path := range paths {
		if value, ok := readKernelConfigOption(path, option); ok {
			return value
		}
	}
	return "unknown"
}

func readKernelConfigOption(path, option string) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()

	var scanner *bufio.Scanner
	if strings.HasSuffix(path, ".gz") {
		gr, err := gzip.NewReader(f)
		if err != nil {
			return "", false
		}
		defer gr.Close()
		scanner = bufio.NewScanner(gr)
	} else {
		scanner = bufio.NewScanner(f)
	}

	key := option + "="
	notSet := "# " + option + " is not set"
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case strings.HasPrefix(line, key):
			return strings.TrimPrefix(line, key), true
		case line == notSet:
			return "n", true
		}
	}

	return "", false
}
