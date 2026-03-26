# Post-Detach Sockmap Latency Plan - 2026-03-26

## Purpose

This note captures the next UX-focused target for the `perf` branch after the
earlier catastrophic native-path regressions were reduced or eliminated.

The priority is **latency first**, not throughput first.

The question for this phase is:

- why does UX still feel sticky or stalled
- after deferred-read parking, no-detach pickup delay, and mux-parent runaway
  were substantially improved

## What Appears Fixed Enough

Recent canaries consistently stopped showing the earlier major failure classes:

- `tls.deferred_read_parked`
- `tls.deferred_read_deadline_overrun`
- `vision.native_runtime_feedback`
- `native_skipped_by_circuit_breaker`
- broad `userspace_idle_timeout` regressions

Recent latency telemetry also suggests these seams are no longer the primary
user-visible problem:

- post-detach handoff is usually a few milliseconds
- local no-detach pickup is now bounded around the
  `visionSignalPollInterval` window rather than multi-second waits

That means the next UX target should not be:

- deferred-read wakeup policy
- generic post-detach handoff timing
- the old `command=1` pickup bug

## Current Read

The remaining measured latency seam is the **post-detach sockmap fallback
loop** in `proxy/proxy.go`.

The recurring pattern in recent logs is:

1. `command=2` arrives and the flow detaches correctly
2. sockmap starts successfully
3. sockmap later becomes inactive for that flow
4. the flow falls back to splice
5. the short splice probe sees zero bytes and emits
   `vision.splice_post_sockmap_stall`
6. the same flow re-enters sockmap again

This is no longer a catastrophic stall in the old sense, but it still creates
user-visible latency on high-value application endpoints such as:

- Google service endpoints
- YouTube endpoints
- Instagram endpoints

In other words: the remaining issue appears to be **oscillation after
sockmap inactivity**, not failure to reach the post-detach fast path.

## Next UX Improvement Target

Make `sockmap_wait_fallback` **terminal and deterministic per flow** rather
than recoverable by repeatedly bouncing between:

- sockmap
- short splice probe
- sockmap again

### Intended Direction

Once a flow has reached `ReasonSockmapWaitFallback`, treat that as evidence
that sockmap is not a good steady-state path for that flow instance.

The plan is:

1. Add a per-flow "sockmap poisoned" concept after `sockmap_wait_fallback`.
2. Prevent that same flow from re-entering sockmap again after the fallback.
3. Choose one stable fallback path for the rest of the flow:
   - prefer splice if it demonstrates progress
   - otherwise fall back to guarded userspace
4. Keep the decision scoped to the current flow, not global policy.

## Why This Target Is Next

This target is a good next step because it is:

- latency-oriented
- local to the remaining measured seam
- narrower than reopening Vision semantics or native read machinery

And it avoids touching areas that now look healthy enough:

- no-detach signal pickup
- deferred Rust read scheduling
- mux parent cost model

## Validation Criteria

The next canary should show:

- fewer or no repeated `CopyRawConn sockmap inactive, falling back to splice`
  events for the same flow
- fewer or no `vision.splice_post_sockmap_stall` events on hot app endpoints
- stable terminal path attribution after a wait-fallback
- no regression back into unbounded splice hangs

## Telemetry To Keep Reading

The most important markers for this phase are:

- `CopyRawConn sockmap inactive, falling back to splice`
- `vision.splice_post_sockmap_stall`
- `post_detach_handoff_path`
- `sockmap_fallback_probe_ns`

Useful supporting markers:

- `vision_signal_source`
- `vision_local_no_detach_wait_ns`
- `vision.native_runtime_feedback`

## Non-Goals For This Phase

Do not reopen these tracks unless a later canary clearly points back to them:

- deferred-read wakeup-ceiling tuning
- `command=1` pickup cadence tuning
- mux-parent lifecycle redesign
- throughput-first optimization work

## Bottom Line

The next UX improvement target is **post-detach sockmap fallback oscillation**.

The branch should stop retrying sockmap indefinitely on the same flow after
`sockmap_wait_fallback`, and instead converge quickly to one stable forwarding
path that minimizes visible latency.
