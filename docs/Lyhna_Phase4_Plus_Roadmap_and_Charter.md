# Lyhna — Phase 4+ Roadmap & Build Charter

**Date:** 2026-06-03
**Author context:** Written at Phase 3 closure to orient the next build instance.
**Companion documents:** `Lyhna_Session_Handoff_Phase3_Closure.md` (read FIRST — what Phase 3 produced)
and `Lyhna_Phase4_Seed_Verifier_Scripts.md` (the Phase 4 starting code).
**Audience:** the next Claude chat instance (strategy/architecture seat), Claude Code (build executor),
and ChatGPT (independent reviewer). Each should be able to pick this up cold.

---

## 0. How to read this document

This is a **sequenced roadmap**, not a single phase spec. It names every remaining build item in
**dependency order** and explains *why that order* — because the ordering is load-bearing and was
decided deliberately. The most important strategic point in this whole document:

> **The stress test (hundreds of sub-agents via Claude Code) is the capstone, NOT the next step.**
> It is tempting to do first because it is the exciting one. It must come LAST, because stressing a
> proof rig with known, deferred soundness gaps proves only that the scaffolding survives load — and
> it floods the corpus with non-production signal (the exact "signal pollution" the architecture
> warns against). Stress-test the thing only after the thing is production-shaped.

Phases below are numbered 4 → 7. Do them in order. Each has: purpose, why-this-order, scope,
invariants, exit condition, and what the next instance needs to start.

---

## 1. Standing invariants (apply to EVERY phase below — never violate)

These do not change phase to phase. A new instance must hold all of them:

- **`lyhna-core` is the FROZEN gate.** The 4-field bind contract (`action_type`, `action_payload`,
  `intent`, `intent_version`), server-resolved authority tiers (caller CANNOT supply tier),
  Ed25519-signed canonical receipts, append-only persistence. No phase below modifies the gate.
- **Fail-closed:** no receipt = no execution.
- **Append-only:** no UPDATE/DELETE on receipts, ever. Nothing is backfilled. (The corpus contains a
  permanent SIGNATURE_INVALID defect receipt and pre-standardization receipts that are kept *because*
  they document history — they are not cleaned up.)
- **The agent never closes its own loop / never attests its own completion.** A separate declared
  authority (runtime boundary, or agent-resolver under human-declared scope) does. This is the
  governing line: *the agent operates inside the loop; the boundary closes the loop; Lyhna signs the proof.*
- **Determinism:** material deltas are DECLARED by the submitting authority, never DETECTED/inferred by
  the system. No probabilistic inference inside the gate.
- **Lane discipline:** `lyhna-core` (gate, frozen) / `lyhna-mcp-proxy` (network adapter) / runtime
  config (Keryke/Hermes). Lanes never cross. Live production binds fire from Adam's terminal; the
  sandbox cannot reach the VPS by design.
- **Multi-AI convergence is the settled-ground bar:** Claude (architect) + Claude Code (builder) +
  ChatGPT (reviewer) converging on the same structural read = settled. Do not re-litigate settled items.
- **Working model:** Adam directs scope; Claude drafts paste-ready prompts; Claude Code executes;
  ChatGPT reviews at gate boundaries; Adam makes all final calls and is a paste-and-run terminal
  (he does not author commands, debug, or do hands-on VPS work — blocks handed to him must be
  paste-and-run clean, no judgment required).

---

## 2. PHASE 4 — The independent offline verifier (NEXT — highest leverage)

### Purpose
Turn the ad-hoc cold-verification done at Phase 3 closure into a **standalone, packaged, offline
verifier** that proves Lyhna's central thesis — *"offline-verifiable, trusts no one"* — as a real
artifact, not a script written once by the architect seat. This is the foundation everything
downstream leans on, and it is the public offline-verify product surface.

### Framing (SETTLED — do not re-open)
Phase 4 is built **productization-shaped**: the real, durable public offline-verify surface that
external parties depend on. Not a throwaway demo. Handle every live signing shape robustly, package as
a real distributable, harden for inputs not anticipated here. There is no external deadline shaping
this phase — build it correctly, not quickly.

### Why this order (first)
- **It is the foundation:** the stress test (Phase 7) is meaningless unless its output can be validated
  at volume. The verifier is what validates. Build the validator before the thing that produces volume.
- **It proves the central thesis as a real artifact:** "trust no one" is unfakeable only if an outsider
  can verify the math themselves with code that depends on nothing from Lyhna but the public key.
- **Discovery is already done:** Phase 3 closure surfaced the full spec input (below). No discovery
  spiral required. Seed code exists (`Lyhna_Phase4_Seed_Verifier_Scripts.md`).

### Critical spec input (from the Phase 3 corpus sweep — DO NOT re-discover)
The production corpus contains **MULTIPLE receipt signing shapes**. A naive verifier fails. Specifically:
- **Standard receipts (majority):** have a `canonical_hash` field. Signed: Ed25519 over the **hex string
  of `canonical_hash`**, where `canonical_hash = sha256(canon(core))` and `core` = the receipt with
  `{signature, public_key, canonical_hash}` removed. Canonicalization = recursive sorted-key, no
  whitespace, JSON-stringified scalars.
- **Newer `authority_resolution` receipts:** have **NO `canonical_hash` field**. Signed: Ed25519 over the
  hex of `sha256(core)` where `core` excludes only `{signature, public_key}` (nothing else to strip).
- **Pre-standardization receipts (small set):** older transitional signing basis; they DO NOT verify
  under either current scheme and **are SUPPOSED to fail** — they predate the scheme that stuck.
- **The permanent SIGNATURE_INVALID defect receipt** (`lrv2_1780276647983_6f9c7ad3`): exists to be
  invalid. A correct verifier must REJECT it. A verifier that "passes everything" is WRONG.
- **`tenant_hash`** must be independently re-derived as `sha256(tenant_id)` and checked, not trusted
  from the receipt.
- **`goal_hash`** (loop receipts) = `sha256(utf8(goal))` hex, no normalization. Must be consistent
  across all occurrences in a chain (`constraints.loop` and `constraints.loop_close`, both scopes).
- **Public key:** single key across the whole corpus,
  `2ecb73042161b7b0008971499b191ec9e3824cd4a6e058a8cede90b04e1efff2`. Raw 32-byte ed25519, hex.
  (SPKI DER prefix for Node: `302a300506032b6570032100` + raw key.)
- **Scope separation:** internal payload carries `tenant_id` only; external carries `tenant_hash` only.
- **Chain verification** (`verifyLoopChain` semantics): head link `prior_receipt_id: null`; each link's
  `prior_receipt_id` resolves to its predecessor; terminal is `action_type: loop_close` carrying both
  `constraints.loop` and `constraints.loop_close`; `action_count` agrees; reject a chain with in-loop
  links but no terminal (unsealed = invalid, detectable).

### Seed code
See `Lyhna_Phase4_Seed_Verifier_Scripts.md` — three working reconstructors from Phase 3 closure
(single-chain verifier, full-corpus sweep, resolution-shape verifier). Start from these. They use a
from-scratch canonicalizer + Node `crypto` (OpenSSL), deliberately NOT the project's `@noble` verifier —
that independence IS the proof. Known seed limitation to fix: the full-corpus sweep assumes every
receipt has `canonical_hash`; the hardened verifier MUST detect receipt shape and apply the correct
scheme per shape.

### Scope
- Standalone module (own repo or a clean package), depends only on a crypto primitive + the public key.
- Input: a single receipt, OR a loop chain, OR a corpus export.
- Output: per-receipt VERIFIED / FAILED with reason; for chains, sealed/unsealed + integrity result.
- Shape-aware: correctly handles all live signing schemes; correctly REJECTS the defect + pre-standard
  receipts; does not require network or the project's own code.
- Reproduces the Phase 3 closure result exactly: 195 verify / 3 fail-by-design on the live corpus export.

### Invariants specific to Phase 4
- Verifier touches nothing live — read-only against exports / pasted receipts.
- Verifier is INDEPENDENT: must not import `lyhna-core` or the proxy's verifier; re-implement the math.
- A correct verifier REJECTS the by-design failures. "All green" is a failure of the verifier.

### Exit condition
A standalone verifier that, run by someone who is not Adam and not the project, against the live corpus
export, reproduces **195 verify / 3 fail-by-design**, correctly identifies why each of the 3 fails,
verifies the Phase 3 chain cold on both scopes, and depends on nothing but the public key + a crypto lib.

### What a new instance needs to start Phase 4
- This document + the Phase 3 closure handoff + the seed scripts doc.
- A live corpus export (CSV manifest exists with `receipt_id` + `canonical_hash`; full signed payloads
  come from Supabase `nstchtapastyzxngcgjf`, table `receipts`, columns `receipt_payload` /
  `external_receipt_payload`, tenant `tenant_d04579fbbb4a`).

---

## 3. PHASE 5 — Adapter soundness: make the per-task proof rig deployable

### Purpose
Convert `lyhna-mcp-proxy` (MCP Adapter v0, per-task, proof-grade) into a production-shaped adapter by
closing the three soundness gaps deliberately deferred at Phase 3. These are the things that make a
stress test (Phase 7) actually *mean* something.

### Why this order (after the verifier, before the stress test)
The verifier (Phase 4) is what proves Phase 5's output is sound. The stress test (Phase 7) is what
proves Phase 5 holds under load. So soundness sits between them: build the validator, harden the thing,
then stress the hardened thing.

### Scope (the three deferred items from Phase 3 section 8)
1. **Kill-guard isolation.** The per-task proxy must run under an identity/PID-namespace the agent
   CANNOT signal or kill. Without this, an agent with a terminal tool (e.g. Chione) can `kill -9` its
   own proxy and force/avoid its own `loop_close` -> self-attestation -> the whole proof collapses. OS/
   harness-level: spawn the proxy under a different UID, or a separate PID namespace/container, or
   sandbox the agent's terminal off the host PID namespace. See `docs/PRODUCTION-ISOLATION.md` in the
   proxy repo — the code seam is already kept open for this; this phase ENFORCES it.
2. **Standing-service close channel.** The per-task model closes on harness SIGTERM. A standing
   (always-on) proxy needs a real runtime->proxy session-control channel to emit `loop_close` per
   session, because process termination of a standing service is not a per-loop boundary. This is a
   genuine new build (the signal does not exist yet — confirmed in Phase 3 discovery: Hermes fires
   `on_session_end` to its engines/memory, NOT to the plugin bus, and the proxy's only non-agent signal
   today is process SIGTERM).
3. **Surface-partition (replace the crude plugin-disable).** Phase 3's proof temporarily DISABLED the
   `lyhna_hermes_bind` plugin to avoid double-binding the MCP surface. Production-correct is a
   PARTITION: the plugin governs the non-MCP surface (terminal, gdrive, hermes-cli) and steps aside ONLY
   on the MCP/Zapier surface (where the proxy governs). CRITICAL: the partition predicate must be
   **fail-closed** — key on a POSITIVE "this is the MCP surface" signal, not a denylist of tool names.
   A denylist fails OPEN when a new tool appears (double-bind or ungoverned); a positive predicate fails
   closed.

### Invariants specific to Phase 5
- Still additive over the frozen gate; `lyhna-core` untouched.
- Each soundness item, once built, gets the fix-and-guard-in-one-pass treatment (the change that fixes
  it also installs the mechanism preventing regression).
- The surface-partition predicate is fail-closed (see above) — non-negotiable.

### Exit condition
A standing or per-task proxy that (a) runs under an identity the governed agent cannot kill, (b) closes
loops on a non-agent signal that survives the standing-service model, and (c) partitions the MCP vs.
non-MCP surface fail-closed — all proven by chains that verify cold (Phase 4 verifier).

### What a new instance needs to start Phase 5
- Phase 4 verifier complete (to validate output).
- The proxy repo on `main` (post the Phase 3 merge — see section 6 hygiene note).
- Read-only discovery of the Hermes runtime session-control surface for item 2 (Phase 3 closure
  section 3/section 6 has the prior discovery; confirm against current runtime).

---

## 4. PHASE 6 — Pricing / metering re-derivation (parallelizable; do before heavy volume)

### Purpose
The current free tier (50K events/mo) is almost certainly off by orders of magnitude against a real
24/7 multi-agent corporate deployment profile — and the stress test (Phase 7) will generate exactly the
volume that exposes this. Re-derive the metering model BEFORE running the stress test, so the stress
test also serves as a real metering data point rather than an unpriced flood.

### Why this order (before the stress test, can overlap Phase 5)
The stress test produces volume. If the metering model is wrong, the stress test either looks free
(misleading) or floods an unpriced tier. Fix the model first so the stress test validates it.

### Scope
- Re-derive event-economics against a realistic always-on multi-agent profile.
- Direction (from prior work): smaller/differently-gated free tier; committed-volume enterprise pricing.
- Canonical source: the Pricing Investor Brief (Free 50K, Growth 50K-500K @ $0.001/event, Scale 500K+ @
  $0.0005/event, Enterprise custom). Re-derive, do not assume current numbers hold.

### Exit condition
A defensible metering model sized to real deployment, ready to be validated by Phase 7 volume.

### Note
This is analysis/strategy, not a gate build — it can proceed in parallel with Phase 5 and does not
touch `lyhna-core`.

---

## 5. PHASE 7 — The stress test (CAPSTONE — hundreds of sub-agents via Claude Code)

### Purpose
Prove the hardened adapter + frozen gate hold under real concurrency and volume: Claude Code fanning out
hundreds of sub-agents (the "16x1000" profile discussed), each running loops through the adapter, all
binding, all chaining, all closing — and the corpus verifying cold at scale.

### Why this order (LAST — this is the whole point of the ordering)
- Stressing the Phase 3 proof rig (per-task, no kill-guard, plugin-disabled) proves only that
  scaffolding survives load. Meaningless for production readiness.
- It must run against the **Phase 5 hardened adapter** (kill-guard enforced, standing close channel,
  surface-partition fail-closed) so the result says something about the real system.
- It must be validatable by the **Phase 4 verifier** at volume.
- It must run against the **Phase 6 metering model** so the volume is a pricing data point, not an
  unpriced flood.
- It generates large corpus volume — which is only legitimate signal if the conditions are
  production-shaped (else it is the "signal pollution" the architecture forbids).

### What the stress test actually validates (the real questions)
- Does the **concurrency mutex** prevent chain forks at scale (hundreds of concurrent `tools/call`
  across many loops)?
- Does **fail-closed** hold when many loops run at once and binds fail under load?
- Does the **close boundary** hold across many simultaneous loops (each closes on its own non-agent
  signal, no cross-contamination)?
- Does the **append-only corpus** stay coherent under write volume?
- Does the **tenant isolation / authority resolution** hold when many agents resolve escalations
  concurrently (the agent-resolver-at-scale model: a human cannot hit approve/refuse/escalate at agent
  velocity — resolution is delegated within human-declared scope, itself a bind, by a DISTINCT authority
  from the acting agent)?
- Does the **IJL corpus** reach the density needed for REDUCER_v1 metrics to become meaningful (this is
  the volume that makes Epoch 1 declaration possible)?

### Invariants specific to Phase 7
- Run only after Phases 4-6. Do not stress-test scaffolding.
- The corpus generated must be under production-shaped conditions, or it is signal pollution — segregate
  or clearly mark test-volume corpus if it is not production-representative.
- Claude Code orchestrates the fan-out however it judges best (Subagents, Agent Teams, Dynamic
  Workflows) — orchestration latitude is full; the invariants (fail-closed, append-only, no
  self-close, lane discipline) are NOT relaxed by scale. Scaling the orchestrator never loosens the
  bind guardrails.

### Exit condition
Hundreds of concurrent agent loops through the hardened adapter produce a corpus that verifies cold at
scale (Phase 4 verifier), with the mutex preventing forks, fail-closed holding, close boundaries
uncontaminated, and metering validated against Phase 6 — demonstrating the system holds under the load
profile of real multi-agent deployment.

### What a new instance needs to start Phase 7
- Phases 4, 5, 6 complete.
- A defined load profile (how many sub-agents, what task shape, what concurrency).
- The Phase 4 verifier wired to run against the generated corpus.

---

## 6. Sequencing summary (the one-screen version)

| Phase | What | Why this order | Touches gate? |
|---|---|---|---|
| **4** | Independent offline verifier (multi-shape, rejects by-design failures) | Foundation for everything; proves the thesis as a real artifact; discovery already done | No |
| **5** | Adapter soundness: kill-guard, standing close channel, fail-closed surface-partition | Makes the stress test meaningful; turns proof rig into deployable adapter | No (additive) |
| **6** | Pricing/metering re-derivation | Fix the model before volume exposes it; can run parallel to 5 | No |
| **7** | Stress test — hundreds of sub-agents via Claude Code | CAPSTONE; only meaningful against a hardened adapter + working verifier + correct metering | No |

**One pre-Phase-4 hygiene action:** merge `lyhna-mcp-proxy` branch `claude/gifted-keller-7e44i` -> `main`
(cold verify was the gate; it passed). Verify 56 tests green ON main post-merge. Proxy-bound session does
this. `lyhna-core` and the VPS copy are untouched by the merge.

---

## 7. For each consuming party

- **Next Claude (architect seat):** read the Phase 3 closure doc first, then this, then the seed scripts.
  Do not re-open settled architecture (section 1 invariants, Path B decision, the deferred list, the
  productization-shaped Phase 4 framing). One step at a time, verified exit conditions, paste-ready
  prompts labeled for their target agent.
- **Claude Code (builder):** Phase 4 is a standalone verifier — own repo, independent of `lyhna-core`
  and the proxy's verifier (re-implement the math; that independence IS the proof). Start from the seed
  scripts. Orchestrate freely. Hold the invariants regardless of how powerful the orchestration gets.
- **ChatGPT (reviewer):** review at gate boundaries. The thing to pressure-test in Phase 4: does the
  verifier correctly REJECT the 3 by-design failures (an "all green" verifier is wrong), and does it
  handle all signing shapes without importing the project's own code? In Phase 5: is the surface-
  partition predicate fail-closed (positive signal, not denylist)? In Phase 7: is the generated corpus
  production-shaped, or is it signal pollution?

---

## 8. Locked governing line (carry into every phase)

**The agent operates inside the loop. The boundary closes the loop. Lyhna signs the proof.**
The gate is frozen. The corpus is append-only. Nothing is backfilled. The verifier trusts no one —
which is exactly why it must reject what is supposed to fail.
