## Xray-core Build Agents

Agents working on this codebase must understand the build pipeline:

### Build Pipeline

`task build` runs: **build-ebpf** → **build-rust** → **build** (Go+CGO link)

- The eBPF and Rust stages are `deps` of the Go build — they run first automatically.
- `task build-pure-go` skips Rust/eBPF entirely (`CGO_ENABLED=0`).

### eBPF Environment Requirements

The eBPF build (`rust/xray-ebpf/`) requires a specific nightly Rust toolchain pinned in `rust/xray-ebpf/rust-toolchain.toml`. Three hazards to be aware of:

1. **bpf-linker version:** Must be installed from cargo (`~/.cargo/bin/bpf-linker`), not Nix. The Nix-packaged version links against an older LLVM and will segfault or emit version mismatch errors. The Taskfile handles this via `CARGO_TARGET_BPFEL_UNKNOWN_NONE_LINKER`.

2. **RUSTUP_TOOLCHAIN:** mise exports `RUSTUP_TOOLCHAIN=stable` globally. The `build-ebpf` task reads the nightly channel from `rust-toolchain.toml` and exports it explicitly. Do not rely on unsetting the variable — go-task's `env: VAR: ""` exports an empty string, not an unset.

3. **LLVM version coupling:** After changing the nightly pin, reinstall bpf-linker against the same nightly: `RUSTUP_TOOLCHAIN=<nightly> cargo install bpf-linker --force`.

### Verification

After building, confirm the binary is correct:
```bash
file xray                          # expect: ELF 64-bit, statically linked, stripped
strings xray | grep xray_blake3   # expect: Rust FFI symbols present
strings xray | grep -c ebpf       # expect: >0 if eBPF bytecode embedded
```

### Git State Authority

When preparing commits or reasoning about branch cleanliness, treat the real git worktree and index as authoritative.

- Sandbox file reads are fine for code inspection and many tests, but they may occasionally reflect an overlay/snapshot view that diverges from the host `.git` state.
- If sandbox `git diff`, staged state, or file dirtiness disagrees with elevated `git status`, `git diff --cached`, or `git log`, trust the real git view and re-check there before staging, committing, or describing branch state.
- Before creating commits, verify the intended series from the real git view with commands like `git status --short`, `git diff --cached --name-only`, and `git log --oneline`.
- Do not infer corruption or half-written files from this mismatch alone; first confirm whether it is only a sandbox-vs-host visibility discrepancy.

---

## DNS Guardrail

DNS is a protected control-plane subsystem on this branch.

When the user asks about performance optimization, acceleration, kTLS, eBPF, sockmap, REALITY, Vision, or similar tuning, **do not change DNS behavior unless the user explicitly asks for DNS work**.

This prohibition includes:

- DNS routing changes
- DNS TCP/UDP rewrite changes
- DNS transport selection changes
- DNS-specific Vision or Mux/XUDP changes
- DNS-specific fallback, timeout, or heuristic tuning

If DNS appears in logs during a performance investigation:

- document it
- analyze it separately
- preserve existing DNS behavior unless the user explicitly authorizes DNS changes

---

## Native REALITY / Vision Guardrail

This branch has already explored and rejected one costly architectural rabbit
hole:

- Rust owns provisional Vision/fallback semantics or semantic events
- Go merely consumes that semantic stream later

Do not default back into that design for performance, kTLS, eBPF, REALITY,
Vision, deferred-ingress, or Track C style work.

For this codebase, treat the safe default boundary as:

- Rust owns handshake/auth, deferred TLS transport, detach, kTLS, and
  stateless/helper primitives
- Go owns Vision command truth, fallback/control-path semantics, and
  camouflage-visible behavior

Additional rules:

- Do not revive the archived Layer 1 semantic bridge as live runtime
  architecture just because its vocabulary is rich or its types look reusable.
- Do not assume a Rust-produced provisional semantic stream is authoritative
  enough for Go to act as a mere consumer.
- Do not respond to native-ingress UX issues by adding timer ladders,
  wake/deadline mazes, or more `command=0` semantic inference.
- Use the archive branch as archaeology/spec input, not as justification for
  wholesale replay on the live execution line.
- If a future task truly requires revisiting split semantic ownership, treat it
  as a research redesign with explicit user buy-in and fresh proof, not as the
  default optimization lane.
- When evaluating native-ingress UX regressions, treat `main` on the same VPS
  with the same client/workload as the behavioral oracle. If `main` works under
  identical conditions, assume the divergence is in this branch until proven
  otherwise.
- Do not blame IG/YouTube/other upstream services, network weather, or request
  volume when the same workload succeeds on the main baseline binary from the
  same server.
- Do not propose request-rate limiting, request shaping, or similar traffic
  reduction as a mitigation for native/Vision regressions unless the user
  explicitly asks for that class of workaround.

This guardrail is meant to prevent undue exploration cost, not to block all
future native work. Native transport/crypto work remains in scope; replaying
the split semantic seam does not.

Do not over-correct into narrow-mindedness or laziness because this line of
work once got lost. The lesson is to choose the boundary more carefully, not to
stop thinking ambitiously.

The archived semantic layer still has lasting value:

- as measurement vocabulary
- as bridge-contract archaeology
- as specification input and potential legacy for future designs

So future agents should preserve curiosity and rigor while avoiding the specific
producer/consumer seam that previously led the branch into the rabbit hole.

### Loopback Native REALITY Guardrail

Loopback is a special case for native REALITY on this branch.

- In `AUTO` mode, loopback listeners and loopback local addresses must skip
  native REALITY. Keep the guard in
  `transport/internet/tcp/native_policy.go`
  (`loopback_listener_auto_guard`).
- `PREFER_NATIVE` and `FORCE_NATIVE` may still override this for explicit
  testing, but do not make loopback native the default path again.
- Do not remove the loopback `AUTO` guard unless the fd-ownership boundary is
  explicitly solved, not merely masked by timing.

Why this guard exists:

- `BlockingGuard` changes the shared file description, not just the dup'd fd.
- During deferred Rust ownership, Go runtime expectations around non-blocking
  fd state and deadline behavior become unreliable on loopback.
- Loopback removes the natural RTT/traffic spacing that often hides this seam
  on remote connections.

Operational rule of thumb:

- If `main` works on the same VPS with the same client/workload, but this
  branch fails only when loopback native REALITY is enabled, assume the
  regression is inside this branch's cross-runtime fd boundary until proven
  otherwise.
- If server-side pipeline logs look healthy while clients report mux churn,
  refresh failures, or intermittent app-level timeouts on loopback, suspect an
  fd-ownership / deferred-runtime boundary issue before blaming upstream
  services.

For the detailed RCA and code references, see
`docs/loopback-native-reality-best-practice-2026-03-24.md`.

---

## Pinecone (Vector Database)

⚠️ **MANDATORY: If you need to help with Pinecone, vector databases, embeddings, semantic search, RAG, or recommendations, you MUST read `.agents/PINECONE.md` first** to determine:

- What questions to ask the user
- How to select the programming language
- Which guide files to consult for implementation details

Do not proceed with Pinecone-related tasks without consulting the appropriate guide files. Use `.agents/PINECONE.md` as your entry point and follow its "Choosing the Right Guide" section to navigate to the appropriate resources.

### Pinecone Instructions Catalog

@./.agents/PINECONE.md
@./.agents/PINECONE-cli.md
@./.agents/PINECONE-python.md
@./.agents/PINECONE-typescript.md
@./.agents/PINECONE-go.md
@./.agents/PINECONE-java.md
@./.agents/PINECONE-quickstart.md
@./.agents/PINECONE-troubleshooting.md
