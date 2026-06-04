# Protocol Correction: receipt verification scheme is selected by signed *kind*, not by envelope shape

**Status:** normative for `lyhna-verify` (Phase 4).
**Audience:** diligence reader / independent reviewer picking this up cold.
**Scope:** how the offline verifier selects which signing scheme to check a
receipt under. This is the load-bearing correctness decision of the verifier.

---

## 1. The corrected rule

> A receipt's verification scheme is selected by its **signed semantic kind**
> (`action_type`), never by an **envelope/structural property** (such as the
> presence of a `canonical_hash` field).

`action_type` lives inside the **signed canonical core** of every receipt.
Therefore the selector is itself signature-covered: an attacker cannot change
which scheme a receipt is judged under without changing the core, which
invalidates the signature. This is precisely what makes kind-routing
**deterministic** rather than **permissive** — the routing key is part of the
proof, not metadata layered on top of it.

The contrast that matters:

| Selector | Tamper-evident? | Verdict |
|---|---|---|
| `action_type` (signed) | Yes — inside the signed core | **correct** |
| `canonical_hash` presence (envelope) | No — structural, not a verdict input | **superseded** |

## 2. The kind → scheme map

The map is **extensible**; today it is binary. New receipt kinds extend the map
with their own canonical scheme — they do not get folded into an existing scheme
by structural resemblance.

### `authority_resolution` → **resolution scheme**
- core = receipt minus `{signature, public_key}` (a `canonical_hash` field, if
  present, is **kept** in core — it is not the signing basis for this kind).
- signed message = the UTF-8 bytes of `hex(sha256(canon(core)))`.

### all other kinds (`bind`, `loop_close`, `inspect_runtime_config`, …) → **standard scheme**
- core = receipt minus `{signature, public_key, canonical_hash}`.
- recompute `sha256(canon(core))` and require it to equal the stored
  `canonical_hash` (internal-consistency check).
- signed message = the UTF-8 bytes of the **hex string** `canonical_hash`.

`canon(...)` is the from-scratch canonicalizer in `src/canon.mjs`: recursive
sorted-key, no whitespace, `JSON.stringify` for scalars.

## 3. Why envelope-presence routing was superseded

The earlier proxy rule — "`canonical_hash` present → standard; absent →
resolution" — was an **implementation proxy** for kind, and it is wrong on the
exact receipts the verifier exists to catch.

The live corpus contains **pre-standardization `authority_resolution`
receipts** that:

1. **carry a `canonical_hash` field**, and
2. **carry a valid *standard-scheme* Ed25519 signature over that
   `canonical_hash`** — i.e., they verify perfectly under the standard scheme.

A presence-based selector routes these to the standard scheme and **validates
their superseded signatures** → a false **all-green**. That is the failure mode
the whole artifact is built to prevent.

Kind-based routing sends them to the **resolution** scheme — the canonical
scheme for `authority_resolution` today — under which they **fail**, because
they were minted on a basis that no longer holds for their kind.

### The verifier is uncharitable by design

One kind, one scheme, **no fallback**. A receipt minted under a *superseded
basis for its kind* fails **forever**, even though it still verifies under the
old basis. The verifier never asks "does this validate under *any* scheme?"; it
asks "does this validate under *the* scheme for its kind?" Charity here would be
a vulnerability: it would resurrect every retired signing basis and erase the
append-only record's own history of correction.

## 4. Empirical proof (the three by-design failures)

These three `authority_resolution` receipts are the evidence and the regression
anchor. Under kind-routing each fails with `SIGNATURE_INVALID`; under
presence-routing each would have been (wrongly) accepted.

| receipt_id | carries `canonical_hash` | verifies under standard scheme | verdict under kind-routing |
|---|---|---|---|
| `lrv2_1780276647983_6f9c7ad3` | yes | yes (valid standard sig) | **FAILED** — permanent SIGNATURE_INVALID defect (Phase 1; exists to be invalid) |
| `lrv2_1780280969194_d02c6928` | yes | yes (valid standard sig) | **FAILED** — pre-standardization resolution receipt (transitional basis) |
| `lrv2_1780354143186_7fe5f993` | yes | yes (valid standard sig) | **FAILED** — pre-standardization resolution receipt (transitional basis) |

The remaining 11 `authority_resolution` receipts carry **no** `canonical_hash`
and verify under the resolution scheme. The 184 non-resolution receipts all
carry `canonical_hash` and verify under the standard scheme. Net:
**195 verify / 3 fail-by-design** across the 198 internal receipts — the Phase 3
closure result, reproduced cold.

## 5. Relationship to the original non-negotiable

The Phase 4 charter's non-negotiable #1 stated the selector as
"`canonical_hash` present → standard; absent → resolution," but its controlling
intent was explicit: *"a permissive fallback would **rescue the by-design
failures** and destroy the proof."* The three receipts above are exactly those
by-design failures, and presence-routing rescues them. **Only the
implementation proxy was corrected; the intent is honored exactly.** Shape is
still detected once, exactly one scheme is applied per receipt, and no fallback
is attempted — the correction makes the selector match the thing it was always
meant to track: the receipt's signed kind.
