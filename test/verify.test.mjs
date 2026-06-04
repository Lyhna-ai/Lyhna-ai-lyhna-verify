// Exit-condition + unit tests for the Lyhna offline verifier.
// Run: node --test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { canon } from '../src/canon.mjs';
import { verifyReceipt, detectShape } from '../src/receipt.mjs';
import { verifyChain } from '../src/chain.mjs';
import { deriveTenantHash, checkTenantPair, checkScopeHygiene } from '../src/tenant.mjs';
import { loadRecords, groupChains } from '../src/input.mjs';
import { rawPublicKeyHex, normalizeSignature } from '../src/ed25519.mjs';
import { LYHNA_PUBLIC_KEY_HEX, BY_DESIGN_FAILURES } from '../src/constants.mjs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CORPUS = join(__dirname, '..', 'corpus', 'corpus.ndjson');
const PIN = { trustedKeyHex: LYHNA_PUBLIC_KEY_HEX };

const records = loadRecords(CORPUS);
const internal = records.filter((r) => r.scope === 'internal');

// ---------------------------------------------------------------------------
// EXIT CONDITION: 195 verify / 3 fail-by-design over the 198 internal receipts.
// ---------------------------------------------------------------------------
test('corpus: 198 internal receipts present', () => {
  assert.equal(internal.length, 198);
});

test('corpus: exactly 195 VERIFIED / 3 FAILED (internal scope)', () => {
  const results = internal.map((r) => verifyReceipt(r.payload, PIN));
  const verified = results.filter((r) => r.status === 'VERIFIED');
  const failed = results.filter((r) => r.status !== 'VERIFIED');
  assert.equal(verified.length, 195, 'expected 195 verified');
  assert.equal(failed.length, 3, 'expected 3 failed');
});

test('corpus: the 3 failures are exactly the documented by-design ids, SIGNATURE_INVALID', () => {
  const failed = internal
    .map((r) => verifyReceipt(r.payload, PIN))
    .filter((r) => r.status !== 'VERIFIED');
  const ids = failed.map((r) => r.receipt_id).sort();
  assert.deepEqual(ids, Object.keys(BY_DESIGN_FAILURES).sort());
  for (const r of failed) assert.equal(r.reason, 'SIGNATURE_INVALID', `${r.receipt_id} reason`);
});

test('corpus: NO receipt outside the by-design set fails ("all green" guard, inverted)', () => {
  const expected = new Set(Object.keys(BY_DESIGN_FAILURES));
  for (const r of internal) {
    const v = verifyReceipt(r.payload, PIN);
    if (!expected.has(r.receipt_id)) {
      assert.equal(v.status, 'VERIFIED', `unexpected failure: ${r.receipt_id} (${v.reason})`);
    }
  }
});

test('corpus: the by-design failures must NOT be rescuable — they stay FAILED', () => {
  // This is the heart of the proof: a permissive verifier would turn these green.
  for (const id of Object.keys(BY_DESIGN_FAILURES)) {
    const rec = internal.find((r) => r.receipt_id === id);
    assert.equal(verifyReceipt(rec.payload, PIN).status, 'FAILED', id);
  }
});

// ---------------------------------------------------------------------------
// CHAINS: Phase 3 chain cold-verifies on both scopes; multi-action chains too.
// ---------------------------------------------------------------------------
test('chains: every loop chain in the corpus verifies cold (both scopes)', () => {
  const { chains } = groupChains(records);
  assert.ok(chains.size >= 1);
  for (const { scope, loop_id, payloads } of chains.values()) {
    const res = verifyChain(payloads, PIN);
    assert.equal(res.status, 'VERIFIED', `chain ${loop_id}/${scope}: ${res.reasons.join(',')}`);
  }
});

test('chains: Phase 3 chain a4a40b55 verifies on internal AND external', () => {
  const { chains } = groupChains(records);
  const scopes = [...chains.values()].filter((c) => c.loop_id === 'a4a40b55-c399-4f4f-b46f-105a53655d3a');
  const seen = new Set(scopes.map((c) => c.scope));
  assert.ok(seen.has('internal') && seen.has('external'), 'both scopes present');
  for (const c of scopes) assert.equal(verifyChain(c.payloads, PIN).status, 'VERIFIED');
});

test('chains: action_count is verified against real link count, not hardcoded to 1', () => {
  const { chains } = groupChains(records);
  const multi = [...chains.values()].find((c) => c.payloads.length > 2);
  assert.ok(multi, 'corpus has a multi-action chain (>2 links)');
  const res = verifyChain(multi.payloads, PIN);
  assert.equal(res.status, 'VERIFIED');
  assert.ok(res.in_loop_links > 1, 'more than one in-loop action');
  assert.equal(res.declared_action_count, res.in_loop_links);
});

test('chains: an unsealed chain (close removed) is REJECTED', () => {
  const { chains } = groupChains(records);
  const c = [...chains.values()].find((c) => c.payloads.length > 1);
  const withoutClose = c.payloads.filter((p) => p.action_type !== 'loop_close');
  const res = verifyChain(withoutClose, PIN);
  assert.equal(res.status, 'FAILED');
  assert.ok(res.reasons.some((r) => r.includes('CLOSE') || r.includes('UNSEALED')));
});

// ---------------------------------------------------------------------------
// TENANT: tenant_hash re-derived, scope separation enforced.
// ---------------------------------------------------------------------------
test('tenant: external tenant_hash == sha256(internal tenant_id) for every pair', () => {
  const byId = new Map();
  for (const r of records) {
    if (!byId.has(r.receipt_id)) byId.set(r.receipt_id, {});
    byId.get(r.receipt_id)[r.scope] = r.payload;
  }
  let pairs = 0;
  for (const { internal: i, external: e } of byId.values()) {
    if (i && e) {
      pairs++;
      assert.ok(checkTenantPair(i, e).ok);
    }
  }
  assert.ok(pairs >= 1);
});

test('tenant: scope hygiene — internal has tenant_id only, external tenant_hash only', () => {
  for (const r of records) {
    const h = checkScopeHygiene(r.payload);
    assert.ok(h.ok, `${r.receipt_id} ${r.scope}: ${h.reason}`);
    assert.equal(h.scope, r.scope);
  }
});

// ---------------------------------------------------------------------------
// UNIT: canon, shape detection, encoding normalization, tamper, trust pin.
// ---------------------------------------------------------------------------
test('canon: recursive sorted-key, no whitespace, stable', () => {
  assert.equal(canon({ b: 1, a: [3, 2, { z: null, a: 'x' }] }), '{"a":[3,2,{"a":"x","z":null}],"b":1}');
  assert.equal(canon(null), 'null');
});

test('shape: keyed on action_type, not canonical_hash presence', () => {
  assert.equal(detectShape({ action_type: 'authority_resolution', canonical_hash: 'deadbeef' }), 'resolution');
  assert.equal(detectShape({ action_type: 'write_file', canonical_hash: 'deadbeef' }), 'standard');
  assert.equal(detectShape({ action_type: 'write_file' }), 'standard');
});

test('encoding: signature normalizes from hex and base64 to the same 64 bytes', () => {
  const sample = internal.find((r) => verifyReceipt(r.payload, PIN).status === 'VERIFIED').payload;
  const fromB64 = normalizeSignature(sample.signature);
  const fromHex = normalizeSignature(fromB64.toString('hex'));
  const fromPrefixed = normalizeSignature('ed25519:' + sample.signature);
  assert.equal(fromB64.length, 64);
  assert.deepEqual(fromB64, fromHex);
  assert.deepEqual(fromB64, fromPrefixed);
});

test('encoding: public key normalizes from hex / base64 / ed25519: to one hex', () => {
  const hex = LYHNA_PUBLIC_KEY_HEX;
  const b64 = Buffer.from(hex, 'hex').toString('base64');
  assert.equal(rawPublicKeyHex(hex), hex);
  assert.equal(rawPublicKeyHex(b64), hex);
  assert.equal(rawPublicKeyHex('ed25519:' + hex), hex);
});

test('tamper: flipping a byte in a verified receipt makes it FAIL', () => {
  const good = internal.find((r) => verifyReceipt(r.payload, PIN).status === 'VERIFIED');
  const tampered = JSON.parse(JSON.stringify(good.payload));
  tampered.outcome = tampered.outcome === 'APPROVED' ? 'REFUSED' : 'APPROVED';
  // canonical_hash now disagrees with core -> CANONICAL_HASH_MISMATCH (standard shape).
  const v = verifyReceipt(tampered, PIN);
  assert.equal(v.status, 'FAILED');
});

test('trust pin: a different pinned key rejects every receipt as UNTRUSTED_PUBLIC_KEY', () => {
  const otherKey = 'f'.repeat(64);
  const good = internal.find((r) => verifyReceipt(r.payload, PIN).status === 'VERIFIED');
  const v = verifyReceipt(good.payload, { trustedKeyHex: otherKey });
  assert.equal(v.status, 'FAILED');
  assert.equal(v.reason, 'UNTRUSTED_PUBLIC_KEY');
});
