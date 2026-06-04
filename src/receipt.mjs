// Per-receipt verification.
//
// SHAPE-DETERMINISTIC, NEVER SCHEME-PERMISSIVE.
// The shape is detected exactly once and exactly one signing scheme is applied
// for that shape. The verifier never "tries schemes until one passes" — a
// permissive fallback would rescue the by-design failures and destroy the proof.
//
// SHAPE KEY = action_type.
//   `authority_resolution`  -> resolution scheme
//   everything else         -> standard scheme
//
// Why action_type and not "canonical_hash present"? The intent of the rule (per
// the build charter) is: "a permissive fallback would RESCUE the by-design
// failures." The three by-design `authority_resolution` receipts each carry a
// VALID `canonical_hash` and a VALID standard-scheme signature over it — so a
// detector keyed on canonical_hash presence routes them to `standard` and
// rescues them (all-green, a WRONG verifier). The signing basis that actually
// produced the corpus result (and the seed scripts) keys the resolution shape
// on action_type, under which those three correctly FAIL. The shape is still a
// deterministic function of the (signed) receipt content, so it cannot be
// gamed: action_type is inside the signed core.
//
//   standard   (action_type !== 'authority_resolution'):
//     core    = receipt minus {signature, public_key, canonical_hash}
//     check   = sha256(canon(core)) === canonical_hash   (internal consistency)
//     signed  = Ed25519 over the UTF-8 bytes of the hex string `canonical_hash`
//
//   resolution (action_type === 'authority_resolution'):
//     core    = receipt minus {signature, public_key}   (canonical_hash, if any,
//               is KEPT in core — it is not the signing basis here)
//     signed  = Ed25519 over the UTF-8 bytes of hex(sha256(canon(core)))
//
// The verdict is purely mechanical. There is no allowlist of "expected to fail"
// receipt ids — the by-design failures fail because the math fails, not because
// they are named.

import { canon } from './canon.mjs';
import {
  normalizePublicKey,
  normalizeSignature,
  verifyEd25519,
  sha256Hex,
  rawPublicKeyHex,
} from './ed25519.mjs';

const STANDARD_ENVELOPE = new Set(['signature', 'public_key', 'canonical_hash']);
const RESOLUTION_ENVELOPE = new Set(['signature', 'public_key']);

export function detectShape(payload) {
  return payload && payload.action_type === 'authority_resolution' ? 'resolution' : 'standard';
}

function coreOf(payload, envelope) {
  const core = {};
  for (const k of Object.keys(payload)) if (!envelope.has(k)) core[k] = payload[k];
  return core;
}

/**
 * Verify one receipt payload.
 * @param {object} payload  the signed receipt object (one scope).
 * @param {object} [opts]
 * @param {string} [opts.trustedKeyHex]  pinned 32-byte public key (hex). When
 *        set, the receipt's embedded key must equal it or the receipt FAILS with
 *        UNTRUSTED_PUBLIC_KEY (the trust anchor — the math alone is not enough).
 * @returns {object} verification result.
 */
export function verifyReceipt(payload, opts = {}) {
  const shape = detectShape(payload);
  const result = {
    receipt_id: payload.receipt_id ?? null,
    action_type: payload.action_type ?? null,
    shape,
    hash: null, // {ok, recomputed, stored}
    signature: null, // boolean
    key_trusted: null, // boolean | null (null when no pin supplied)
    status: 'FAILED',
    reason: null,
  };

  if (typeof payload !== 'object' || payload === null) {
    result.reason = 'NOT_AN_OBJECT';
    return result;
  }
  if (!payload.signature || !payload.public_key) {
    result.reason = 'MISSING_SIGNATURE_OR_KEY';
    return result;
  }

  // Build the exact bytes that should have been signed, per shape.
  let message;
  if (shape === 'standard') {
    if (!Object.prototype.hasOwnProperty.call(payload, 'canonical_hash')) {
      // Standard shape with no canonical_hash to sign over — fail closed.
      result.reason = 'MISSING_CANONICAL_HASH';
      return result;
    }
    const recomputed = sha256Hex(canon(coreOf(payload, STANDARD_ENVELOPE)));
    const stored = payload.canonical_hash;
    result.hash = { ok: recomputed === stored, recomputed, stored };
    // Signature is over the hex STRING of canonical_hash, exactly as stored.
    message = Buffer.from(String(stored), 'utf8');
  } else {
    const h = sha256Hex(canon(coreOf(payload, RESOLUTION_ENVELOPE)));
    result.hash = { ok: true, recomputed: h, stored: null };
    message = Buffer.from(h, 'utf8');
  }

  // Trust pin: the embedded key must match the pinned key (if provided).
  let embeddedHex;
  try {
    embeddedHex = rawPublicKeyHex(payload.public_key);
  } catch {
    result.reason = 'BAD_PUBLIC_KEY_ENCODING';
    return result;
  }
  if (opts.trustedKeyHex) {
    result.key_trusted = embeddedHex === String(opts.trustedKeyHex).toLowerCase();
  }

  // The one and only signature check.
  let sigOK = false;
  try {
    const key = normalizePublicKey(payload.public_key);
    const sig = normalizeSignature(payload.signature);
    sigOK = verifyEd25519(message, sig, key);
  } catch (e) {
    result.signature = false;
    result.reason = 'SIGNATURE_VERIFY_ERROR:' + e.message;
    return result;
  }
  result.signature = sigOK;

  // Verdict — deterministic, fail-closed.
  if (shape === 'standard' && !result.hash.ok && !sigOK) {
    result.reason = 'CANONICAL_HASH_MISMATCH+SIGNATURE_INVALID';
    return result;
  }
  if (shape === 'standard' && !result.hash.ok) {
    result.reason = 'CANONICAL_HASH_MISMATCH';
    return result;
  }
  if (!sigOK) {
    result.reason = 'SIGNATURE_INVALID';
    return result;
  }
  if (opts.trustedKeyHex && !result.key_trusted) {
    result.reason = 'UNTRUSTED_PUBLIC_KEY';
    return result;
  }
  result.status = 'VERIFIED';
  result.reason = 'OK';
  return result;
}
