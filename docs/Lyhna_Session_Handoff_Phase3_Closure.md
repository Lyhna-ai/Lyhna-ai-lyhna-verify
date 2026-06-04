# Lyhna — Session Handoff: Phase 3 Closure (MCP Adapter v0)

**Date:** 2026-06-03
**Status:** Phase 3 CLOSED — proven by independent cold verification on the production corpus.
**Prior handoff:** Phase 2b → Phase 3 (loop chain mechanism established in `@lyhna/bind`).

---

## 1. What Phase 3 was

Phase 3 = **MCP Adapter v0 for Lyhna** — a durable, runtime-agnostic MCP execution-boundary surface
(`lyhna-mcp-proxy`) that sits between an agent runtime and its tools, governing each `tools/call`
with a loop-bound, chained Lyhna receipt. **Chione (Hermes runtime) was the test fixture, not the
deliverable.** The deliverable is the adapter; it survives Chione.

**Governing line (locked):** The agent operates inside the loop. The proxy/runtime boundary closes
the loop. Lyhna signs the proof. The agent NEVER closes its own loop — self-attestation of completion
is the asset-destroyer (CISA violation).

---

## 2. The architecture decision trail (settled — do not re-litigate)

- **Close-boundary problem:** Step 0 discovery proved the loop close was, in the SDK, an agent
  self-declaration (`closeLoop()` rides `bind()`). That boundary did not exist in any lane. This was
  the load-bearing Phase 3 problem.
- **Path A (fork Hermes host) REJECTED:** would make Lyhna's boundary depend on modifying Nous's
  Hermes internals to surface `on_session_end` to the plugin bus (the bus reaches only
  `pre_tool_call`/`post_tool_call`, never session lifecycle — confirmed by reading Hermes Python core).
  Wrong ownership shape; Hermes-only; dies with the fixture.
- **Path B (proxy adapter) CHOSEN:** `lyhna-mcp-proxy` becomes the per-task session boundary. Harness
  opens the loop + injects `loop_id`; proxy stamps `constraints.loop` on every intercepted bind; close
  rides a harness-controlled SIGTERM → proxy emits `loop_close` in `shutdown()`. Builds the reusable
  surface; leaves Nous untouched.
- **Per-task, NOT standing service:** for the proof, the proxy is spawned per task and torn down by
  harness SIGTERM. Standing-service productization (needs a runtime→proxy control channel) is deferred.

## 3. Five build points (all landed, gate frozen)

1. **Loop-context threading** — additive `constraints.loop {loop_id, prior_receipt_id, goal_hash}`
   merged over caller constraints, never clobbering server-appended fields; `prior_receipt_id`
   advances to returned `receipt_id`; root is `null`; caller `authority_tier` stripped.
2. **Terminal close on SIGTERM** — `loop_close` emitted before transport teardown, carrying
   `constraints.loop_close {loop_id, goal_hash, action_count, outcome, prior_receipt_id,
   termination_reason}`. SIGTERM-only; no idle timeout.
3. **Grace window + retry** — `shutdown()` awaits the close POST; retries within
   `LYHNA_PROXY_LOOP_CLOSE_GRACE_MS` (default 5000ms); ultimate failure leaves chain unsealed (detectable).
4. **Concurrency mutex** — serializes read-prior → bind → set-prior so concurrent `tools/call` cannot
   fork the chain onto a shared `prior_receipt_id`.
5. **Unsealed-chain detection** — `verifyLoopChain` rejects a chain with in-loop links but no terminal
   `loop_close`, plus broken continuity, loop_id mismatch, duplicate/non-terminal close, action_count
   disagreement.
6. **Production-isolation spec (written, not enforced on fixture)** — `docs/PRODUCTION-ISOLATION.md`:
   in real deployment the proxy must run under an identity/PID-namespace the agent cannot signal/kill.
   The kill-guard is a documented production requirement, deferred for the throwaway fixture proof.

## 4. Provenance reconciliation (critical — the gap that was closed)

The proxy was first built mirroring the loop mechanism from a **prose contract**, because the canonical
`lyhna-bind/src/loop.ts` was not mounted in the build session. A reconciliation pass against the real
`loop.ts` (v0.3.9) found **5 of 6 field points mismatched** — all signature-breaking, because they sit
in the signed canonical core:
- close `action_type` was `lyhna.loop.close` → corrected to `loop_close`
- close `action_payload` was `{loop_id, goal_hash}` → corrected to `{loop_id, action_count}`
- close `intent_version` was `1.0` → corrected to `loop_v1`
- close `constraints` was `{loop_close}` only → corrected to `{loop, loop_close}` (goal_hash in both)
- `goal_hash` was read from env (never computed) → corrected to derived `sha256(utf8(goal))` hex,
  byte-equivalent to canonical `bytesToHex(sha256(utf8ToBytes(goal)))`, no normalization.
Point 1 (additive merge) matched. After reconciliation: 56/56 tests green.
**Lesson:** field *shape* matching is insufficient; field *derivation* (esp. goal_hash) is what cold
verification turns on.

## 5. The live run (the proof)

- **loop_id:** `a4a40b55-c399-4f4f-b46f-105a53655d3a`
- **Config (temporary, restored after):** `lyhna_hermes_bind` plugin disabled (avoid double-bind on
  the MCP surface); Chione's `mcp_servers.zapier.url` repointed to `http://127.0.0.1:8765/mcp`; proxy
  dialed Zapier Streamable-HTTP upstream; bind fired at production (`api.lyhna.com`), Chione's existing
  key reused.
- **Two receipts produced:**
  - Head: `lrv2_1780456493799_44bf5f1b` — `inspect_runtime_config`, tier_0, `runtime_mapped`,
    `prior_receipt_id: null`. (Tool actually called: `list_enabled_zapier_actions`, a read.)
  - Close: `lrv2_1780456640800_34f62968` — `loop_close`, tier_2, resolved via `tenant_extension`,
    `action_count: 1`, `outcome: COMPLETED`, `termination_reason: SIGTERM`, linking back to head.
- Both in production Supabase `nstchtapastyzxngcgjf`, same corpus/key lineage as 2b.

**NOTE on test surface:** Zapier was the wrong (highest-friction) surface for a universal-adapter
proof — it has a non-standard Streamable-HTTP/URL-token MCP interface that forced HTTP-upstream work.
A generic stdio MCP upstream would have proven the identical claim with none of the friction. The
adapter's claim is universal at the `tools/call` layer; the upstream identity is irrelevant to the proof.

## 6. Cold verification (the actual proof — "by math, trusts no one")

Independent reconstruct, from-scratch canonicalizer + Node OpenSSL Ed25519 (NOT the project verifier,
NOT the proxy's own verifier):

**Phase 3 chain (both scopes):** All 4 payloads (head + close, internal + external) — `canonical_hash`
reconstructed, Ed25519 signature verified over the hex string of the hash, `tenant_hash` re-derived as
`sha256(tenant_id)`, `goal_hash` consistent across all 6 occurrences, scope separation clean
(internal carries `tenant_id` only, external `tenant_hash` only). **VERIFIES COLD ON BOTH SCOPES.**

**Full corpus sweep (198 receipts, tenant_d04579fbbb4a):**
- **195 verify cold.** Single signing key across the corpus (`2ecb73…fff2`) — no key drift.
  - 184 standard receipts: sign over hex of `sha256(core)` where core excludes
    `{signature, public_key, canonical_hash}`.
  - 11 newer `authority_resolution` receipts: NO `canonical_hash` field; sign over hex of `sha256(core)`
    where core excludes only `{signature, public_key}`.
- **3 do NOT verify — intentional and append-only:**
  - `lrv2_1780276647983_6f9c7ad3` — permanent SIGNATURE_INVALID defect receipt (Phase 1); exists to be
    invalid; enforcement layer preserving its own defect.
  - `lrv2_1780280969194_d02c6928`, `lrv2_1780354143186_7fe5f993` — pre-standardization resolution
    receipts on a transitional signing basis.
- Zero unexplained failures; nothing backfilled to make old receipts verify under the new scheme.

**Phase 4 input surfaced:** the corpus has MULTIPLE receipt-signing shapes (standard / no-canonical_hash
resolution / transitional). The public offline verifier must handle all live schemes AND correctly
EXPECT the defect receipt to fail. A naive verifier rejecting anything without `canonical_hash` would
wrongly fail 11 valid resolution receipts.

## 7. Status of artifacts

- **Adapter:** `lyhna-mcp-proxy`, commit `7cb8beb86cc18532f232af001cc528343259b4c4`, branch
  `claude/gifted-keller-7e44i`, 56/56 green. Merge to `main` is the one pre-Friday code action
  (verify 56 green ON main post-merge). VPS copy at `/root/lyhna-mcp-proxy` is checked out to the
  branch and is NOT auto-updated by the merge — does not need re-syncing before the meeting.
- **`lyhna-core`:** FROZEN, untouched throughout Phase 3.
- **Corpus:** 198 events, production Supabase `nstchtapastyzxngcgjf`, dashboard shows Phase 3 pair
  VERIFIED at top of ledger.

## 8. What is NOT done (deferred, by decision — name as roadmap, do not build before Friday)

- Standing-service productization (runtime→proxy control channel for per-session close).
- Kill-guard isolation (proxy under non-agent UID/PID-namespace) — documented production requirement.
- Surface-partition (plugin steps aside only on MCP surface) instead of full plugin-disable.
- Multi-shape public verifier (Phase 4) — must handle all signing shapes + expect defect receipt to fail.
- Heavier multi-step task (this proof was a 1-action loop).

## 9. Where things stand vs. last week

Last week: "Lyhna issues signed receipts; the gate enforces." This week: a live autonomous agent,
governed through a runtime adapter, produced a loop chain whose close was driven by the boundary
(SIGTERM), not the agent — verifying cold on both scopes by a reconstruct that trusts no one; plus a
198-receipt corpus where 195 verify and 3 fail by design. The central claim moved from asserted to
demonstrated against the skeptical direction.

**Next external step:** VC technical diligence — their engineer reviews the system. Prepare: (1) technical
narrative doc at engineer altitude, (2) the independent verifier packaged so their engineer can run it,
(3) honest known-issues/roadmap doc. Freeze the build; package the truth.
