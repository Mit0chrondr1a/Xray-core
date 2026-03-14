# Native REALITY Layer 1 Archive - 2026-03-14

## Purpose

This note records where the committed Layer 1 legacy from the native-REALITY
exploration now lives after the retreat merge slimmed `perf` back down to the
validated salvage boundary.

The goal is to preserve the good part of the rabbit hole:

- the measurement vocabulary
- the semantic bridge taxonomy
- the probe/oracle terminology
- the Track C design input

without keeping the whole Layer 1 runtime surface active on the execution
branch.

Related notes:

- [native-reality-improvement-plan-2026-03-13.md](/home/ryan/Xray-core/docs/native-reality-improvement-plan-2026-03-13.md)
- [native-reality-improvement-strategy-2026-03-13.md](/home/ryan/Xray-core/docs/native-reality-improvement-strategy-2026-03-13.md)
- [native-reality-rust-retreat-salvage-map-2026-03-14.md](/home/ryan/Xray-core/docs/native-reality-rust-retreat-salvage-map-2026-03-14.md)
- [native-reality-rust-handshake-boundary-2026-03-14.md](/home/ryan/Xray-core/docs/native-reality-rust-handshake-boundary-2026-03-14.md)

## Archive Branch

The archived Layer 1 code is pinned on:

- `archive/native-reality-layer1-2026-03-14`

That branch points to:

- commit `060433e0` `feat(tcp): add scoped native reality probe consumers`

This is the last pre-retreat `perf` head and the committed 13-commit Layer 1
range identified in the external review:

- `rust..060433e0`

At the time of archiving, that range is:

1. `ec5050a4` `refactor(proxy): make vision transition contract explicit`
2. `667456fb` `feat(proxy): add vision transition compatibility oracle`
3. `15860154` `feat(proxy): correlate vision seam traces with ingress origin`
4. `5007f8f5` `feat(proxy): trace vision semantic progression at the seam`
5. `f8a4d7aa` `feat(proxy): summarize vision seam progression per flow`
6. `41896687` `feat(proxy): record vision seam semantic outcomes`
7. `70dbac9a` `refactor(proxy): unify vision ingress origin under seam bridge`
8. `38edcee7` `refactor(proxy): make vision drain facts producer-owned`
9. `f69c3b58` `feat(proxy): bridge native transport lifecycle into vision seam`
10. `95684a3e` `feat(proxy): add scoped native reality seam probe bridge`
11. `94d9ae11` `feat(tls): publish deferred rust provisional lifecycle`
12. `76e67711` `feat(proxy): model native provisional lifecycle in vision seam`
13. `060433e0` `feat(tcp): add scoped native reality probe consumers`

## What This Archive Preserves

The archive branch preserves the Layer 1 measurement and semantic vocabulary
that the external review judged architecturally sound.

The most important preserved assets are:

- `proxy/vision_transition.go`
  - the transition/bridge/oracle/probe vocabulary
  - semantic event taxonomy and snapshot types
  - bridge assessment and pending-gap classification
- `transport/internet/tls/tls.go`
  - deferred provisional lifecycle publication
  - transport-side event kinds and lifecycle observation hooks
- `transport/internet/tcp/native_policy.go`
  - scoped probe consumer policy
- `transport/internet/tcp/hub.go`
  - native probe entry points at ingress

These assets are preserved because they remain useful as:

- Track C design input
- semantic vocabulary reference
- bridge-contract archaeology
- a source for future extracted spec/types if we later decide to rebuild a
  cleaner semantic boundary

## What The Archive Does Not Mean

Archiving Layer 1 does **not** mean:

- restoring `vision_transition.go` to the active `perf` runtime
- treating Layer 1 as the default execution line
- undoing the handshake-boundary correction
- reopening the large response-loop seam engine

The current live direction remains:

- `rust` as the code baseline
- `main` as the UX oracle
- the slim salvage boundary on `perf`
- canonical Vision padding owned by Go
- Rust kept at handshake/native-truth and non-Vision acceleration boundaries

In other words:

- Layer 1 is preserved as an architectural asset
- not as live production architecture on the current execution branch

## Why Archive Instead Of Keep Live

This split is deliberate.

The retreat succeeded partly because the active execution branch stopped
carrying the large transition engine as live runtime code. Reintroducing it
just to avoid losing vocabulary would recreate architectural gravity toward the
same seam that caused the rabbit hole.

The archive branch solves that cleanly:

- it preserves the exact code and commit history
- it keeps the vocabulary recoverable
- it avoids keeping the whole measurement layer in the active runtime path

That is the healthy compromise between:

- "delete it all"
- and
- "keep it all active forever"

## How To Use This Archive

Use the archive branch when you need:

- the original Layer 1 transition vocabulary
- the exact semantic bridge taxonomy
- the probe/oracle contract history
- a code reference while writing future Track C specifications

Do **not** use it as justification for wholesale replay onto `perf`.

The acceptable uses are:

1. extract specification language into docs
2. port small neutral type definitions into a future dedicated package
3. compare current behavior against the old measurement vocabulary
4. mine specific test ideas or event naming for Track C

The unacceptable use is:

- reactivating the archived Layer 1 runtime surface on the live execution line
  without a new architectural decision

## Practical Inspection Commands

Useful commands:

```bash
git log --oneline rust..archive/native-reality-layer1-2026-03-14
git show archive/native-reality-layer1-2026-03-14:proxy/vision_transition.go
git diff rust..archive/native-reality-layer1-2026-03-14 -- proxy/vision_transition.go
```

## Final Position

Layer 1 legacy is worth keeping.

It is not worth keeping live on the current branch.

The archive branch is the agreed compromise:

- preserve the semantic measurement legacy exactly
- keep the execution line slim and boundary-correct
- leave Track C with real source material instead of memory
