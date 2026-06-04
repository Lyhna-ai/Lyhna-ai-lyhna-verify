# lyhna-verify

**Independent, offline verifier for the Lyhna receipt corpus.** The public
"trusts no one" artifact: it re-implements canonicalization and Ed25519
verification from scratch and depends on **nothing** but Node's built-in
`crypto` (OpenSSL) and a single pinned public key. It does not import
`@lyhna/bind`, `lyhna-core`, or the proxy's verifier — that independence *is* the
proof.

Run by anyone, against the corpus export, it reproduces the Phase 3 closure
result exactly:

```
internal: 195 VERIFIED / 3 FAILED (of 198)
chains:   5/5 verified (both scopes)
tenant_hash re-derivation: all match
EXPECTATION MET — 195 verify / 3 fail-by-design reproduced, chains cold-verified.
```

A verifier that turns the three by-design failures green is **wrong**. This one
rejects them — by math, not by an allowlist.

## Install / run

Zero dependencies. Requires Node ≥ 18.

```bash
# Full corpus sweep (the exit-condition proof)
node bin/lyhna-verify.mjs --corpus corpus/corpus.ndjson

# A single receipt (auto-detected)
node bin/lyhna-verify.mjs examples/single-verified.json
node bin/lyhna-verify.mjs examples/single-by-design-failure.json   # exits non-zero

# A loop chain
node bin/lyhna-verify.mjs --chain examples/phase3-chain-internal.json

# Machine-readable
node bin/lyhna-verify.mjs --corpus corpus/corpus.ndjson --json

# Verify the math only, without pinning a trusted key
node bin/lyhna-verify.mjs --corpus corpus/corpus.ndjson --no-pin

# Pin a different signer
node bin/lyhna-verify.mjs --corpus corpus/corpus.ndjson --pubkey <hex|base64|ed25519:...>

# Tests (includes the exit-condition assertions)
node --test
```

Exit code is `0` only when the result matches expectation: in corpus mode that
means the documented three fail **and** everything else verifies **and** all
chains verify **and** every tenant pair re-derives.

## What it checks

**Per receipt** → `VERIFIED` / `FAILED`, with: shape detected, hash result,
signature result, and failure reason.

**Per chain** → `sealed` / `unsealed` + full integrity (continuity, single head,
single terminal close, constant `loop_id`, consistent `goal_hash`, declared
`action_count` == real in-loop link count).

## The two signing shapes (shape-deterministic, never scheme-permissive)

The shape is detected **once**, and **exactly one** scheme is applied. The
verifier never tries schemes until one passes — a permissive fallback would
rescue the by-design failures and destroy the proof.

| Shape | When | core (stripped of) | Signed message |
|---|---|---|---|
| **standard** | `action_type !== 'authority_resolution'` | `{signature, public_key, canonical_hash}` | UTF-8 bytes of the hex string `canonical_hash` (and `sha256(canon(core)) == canonical_hash` is checked) |
| **resolution** | `action_type === 'authority_resolution'` | `{signature, public_key}` (canonical_hash **kept**) | UTF-8 bytes of `hex(sha256(canon(core)))` |

Canonicalization is recursive sorted-key, no whitespace, `JSON.stringify` for
scalars (`src/canon.mjs`).

### Why the shape is keyed on `action_type`, not `canonical_hash` presence

This is the one place the implementation deviates — deliberately — from the
literal wording of the build charter, and the reason is load-bearing:

- The charter's stated rule was "`canonical_hash` present → standard; absent →
  resolution," with the controlling intent that "a permissive fallback would
  **rescue the by-design failures**."
- The three by-design `authority_resolution` receipts
  (`lrv2_1780276647983_6f9c7ad3`, `lrv2_1780280969194_d02c6928`,
  `lrv2_1780354143186_7fe5f993`) each carry a **valid** `canonical_hash` *and* a
  **valid standard-scheme Ed25519 signature over it**. A detector keyed on
  `canonical_hash` presence therefore routes them to `standard` and **verifies
  them** — the exact rescue the charter forbids, producing an all-green (wrong)
  verifier.
- Keying the resolution shape on `action_type` (as the Phase 3 seed scripts
  actually did) routes those three to the resolution scheme, under which they
  correctly **fail**. The partition is unambiguous in the live corpus: all 184
  non-resolution receipts carry `canonical_hash`; the 14 `authority_resolution`
  receipts split 11 (no hash, verify) + 3 (with hash, fail by design).

The shape stays a deterministic function of the **signed** receipt content
(`action_type` is inside the signed core), so it cannot be gamed: changing
`action_type` to pick a favorable scheme invalidates the signature.

## The three by-design failures (must stay FAILED)

| receipt_id | mechanical reason | documented cause |
|---|---|---|
| `lrv2_1780276647983_6f9c7ad3` | `SIGNATURE_INVALID` | permanent SIGNATURE_INVALID defect (Phase 1; exists to be invalid) |
| `lrv2_1780280969194_d02c6928` | `SIGNATURE_INVALID` | pre-standardization resolution receipt (transitional signing basis) |
| `lrv2_1780354143186_7fe5f993` | `SIGNATURE_INVALID` | pre-standardization resolution receipt (transitional signing basis) |

The `receipt_id → cause` map (`src/constants.mjs`) is used for **reporting
only** — it never influences a verdict.

## Tenant binding

`tenant_hash` is **re-derived** as `sha256(tenant_id)` and never trusted from
the receipt. Scope separation is enforced: internal carries `tenant_id` only,
external carries `tenant_hash` only. Where both scopes of a receipt are present,
the external `tenant_hash` is re-derived from the internal `tenant_id` and
compared.

`goal_hash` is checked for **consistency** across a chain only — the plaintext
goal is never demanded (the corpus is content-blind).

## Trust root

The single Ed25519 public key across the whole corpus
(`2ecb73…fff2`, raw 32-byte hex; SPKI DER prefix
`302a300506032b6570032100`). Pinned in `src/constants.mjs`, overridable with
`--pubkey`. Signatures and keys are accepted as base64, base64url, hex, or with
an `ed25519:` prefix; the verification math is not permissive.

## Layout

```
bin/lyhna-verify.mjs   CLI
src/canon.mjs          from-scratch canonicalization
src/ed25519.mjs        OpenSSL Ed25519 + encoding normalization
src/receipt.mjs        shape detection + per-receipt verification
src/chain.mjs          arbitrary-length loop-chain verification
src/tenant.mjs         tenant_hash re-derivation + scope hygiene
src/input.mjs          single / array / NDJSON / bundle loading
src/constants.mjs      pinned key + by-design annotations
corpus/corpus.ndjson   the live export (205 lines: 198 internal + 7 external)
examples/              sample inputs for each mode
test/verify.test.mjs   exit-condition + unit tests (node --test)
```

## Independence & read-only

Re-implements the math; imports no Lyhna code. Touches nothing live — it reads
an export. The corpus export in `corpus/` was pulled read-only from the
production store and its integrity was checked against a server-side MD5 at
export time.
