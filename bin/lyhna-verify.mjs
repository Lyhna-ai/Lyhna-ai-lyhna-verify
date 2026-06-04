#!/usr/bin/env node
// lyhna-verify — independent, offline verifier CLI for the Lyhna receipt corpus.
//
// Usage:
//   lyhna-verify <file>                auto-detect (single | chain | corpus)
//   lyhna-verify --receipt <file>      verify a single receipt
//   lyhna-verify --chain   <file>      verify a loop chain (grouped by scope+loop_id)
//   lyhna-verify --corpus  <file>      sweep a corpus NDJSON export
//
// Options:
//   --pubkey <hex|base64|ed25519:...>  pin a different signer (default: corpus key)
//   --no-pin                           do not pin a trusted key (math only)
//   --json                             machine-readable JSON output
//   --quiet                            summary only (no per-receipt lines)
//
// Exit code: 0 if every receipt's status matches expectation and all chains
// verify; 1 otherwise. "Expectation": a verifier that turns the by-design
// failures green is WRONG, so corpus mode succeeds only when the documented
// 3 fail AND everything else verifies.

import { verifyReceipt } from '../src/receipt.mjs';
import { verifyChain } from '../src/chain.mjs';
import { loadRecords, groupChains } from '../src/input.mjs';
import { checkScopeHygiene, checkTenantPair } from '../src/tenant.mjs';
import { rawPublicKeyHex } from '../src/ed25519.mjs';
import { LYHNA_PUBLIC_KEY_HEX, BY_DESIGN_FAILURES } from '../src/constants.mjs';

function parseArgs(argv) {
  const opts = { mode: 'auto', file: null, json: false, quiet: false, pin: true, pubkey: LYHNA_PUBLIC_KEY_HEX };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--receipt') opts.mode = 'receipt';
    else if (a === '--chain') opts.mode = 'chain';
    else if (a === '--corpus') opts.mode = 'corpus';
    else if (a === '--json') opts.json = true;
    else if (a === '--quiet') opts.quiet = true;
    else if (a === '--no-pin') opts.pin = false;
    else if (a === '--pubkey') opts.pubkey = argv[++i];
    else if (a === '-h' || a === '--help') opts.help = true;
    else if (!a.startsWith('-')) opts.file = a;
  }
  return opts;
}

const HELP = `lyhna-verify — independent offline verifier for Lyhna receipts

  lyhna-verify <file>            auto-detect single / chain / corpus
  lyhna-verify --receipt <file>
  lyhna-verify --chain   <file>
  lyhna-verify --corpus  <file>

  --pubkey <key>   pin a different signer key (hex/base64/ed25519:)
  --no-pin         verify the math only, do not pin a trusted key
  --json           machine-readable output
  --quiet          summary only
`;

function styleStatus(s) {
  if (!process.stdout.isTTY) return s;
  return s === 'VERIFIED' ? `\x1b[32m${s}\x1b[0m` : `\x1b[31m${s}\x1b[0m`;
}

function printReceiptLine(r) {
  const hash = r.hash ? (r.shape === 'standard' ? (r.hash.ok ? 'hash OK' : 'hash FAIL') : 'hash n/a') : 'hash n/a';
  const sig = r.signature === true ? 'sig OK' : r.signature === false ? 'sig FAIL' : 'sig n/a';
  const id = (r.receipt_id || '(no id)').padEnd(28);
  console.log(`  ${styleStatus(r.status.padEnd(8))} ${id} ${r.shape.padEnd(10)} ${hash.padEnd(9)} ${sig.padEnd(8)} ${r.reason}`);
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help || !opts.file) {
    console.log(HELP);
    process.exit(opts.file ? 0 : 1);
  }

  const trustedKeyHex = opts.pin ? rawPublicKeyHex(opts.pubkey) : undefined;
  const vopts = trustedKeyHex ? { trustedKeyHex } : {};

  let records;
  try {
    records = loadRecords(opts.file);
  } catch (e) {
    console.error(`error: cannot load ${opts.file}: ${e.message}`);
    process.exit(2);
  }

  // Decide effective mode.
  let mode = opts.mode;
  if (mode === 'auto') {
    if (records.length === 1) mode = 'receipt';
    else {
      const anyLoop = records.some((r) => r.payload?.constraints?.loop);
      mode = anyLoop && records.length <= 64 ? 'chain' : 'corpus';
    }
  }

  if (mode === 'receipt') return runReceipt(records, vopts, opts);
  if (mode === 'chain') return runChain(records, vopts, opts);
  return runCorpus(records, vopts, opts);
}

function runReceipt(records, vopts, opts) {
  const results = records.map((rec) => ({
    ...verifyReceipt(rec.payload, vopts),
    scope: rec.scope,
    scope_hygiene: checkScopeHygiene(rec.payload),
  }));
  const allOK = results.every((r) => r.status === 'VERIFIED');
  if (opts.json) console.log(JSON.stringify({ mode: 'receipt', results }, null, 2));
  else {
    console.log('=== SINGLE RECEIPT VERIFICATION ===');
    results.forEach(printReceiptLine);
  }
  process.exit(allOK ? 0 : 1);
}

function runChain(records, vopts, opts) {
  const { chains } = groupChains(records);
  const report = [];
  let allOK = chains.size > 0;
  for (const { scope, loop_id, payloads } of chains.values()) {
    const res = verifyChain(payloads, vopts);
    report.push({ scope, loop_id, ...res });
    if (res.status !== 'VERIFIED') allOK = false;
  }
  if (opts.json) {
    console.log(JSON.stringify({ mode: 'chain', chains: report }, null, 2));
  } else {
    console.log('=== LOOP CHAIN VERIFICATION ===');
    for (const c of report) {
      console.log(`\n  loop ${c.loop_id}  scope=${c.scope}  links=${c.length}`);
      console.log(`    ${styleStatus(c.status)}  sealed=${c.sealed} continuity=${c.continuity_ok} ` +
        `loop_id_consistent=${c.loop_id_consistent} goal_hash_consistent=${c.goal_hash_consistent} ` +
        `action_count ${c.declared_action_count}==${c.in_loop_links}:${c.action_count_ok}`);
      if (c.status !== 'VERIFIED') console.log(`    reasons: ${c.reasons.join(', ')}`);
      if (!opts.quiet) for (const r of c.receipts) console.log(`      - ${r.status.padEnd(8)} ${r.action_type} ${r.receipt_id} (${r.reason})`);
    }
  }
  process.exit(allOK ? 0 : 1);
}

function runCorpus(records, vopts, opts) {
  // Verify every record. Pair scopes by receipt_id for tenant cross-checks.
  const byId = new Map();
  for (const rec of records) {
    if (!byId.has(rec.receipt_id)) byId.set(rec.receipt_id, {});
    byId.get(rec.receipt_id)[rec.scope] = rec.payload;
  }

  const results = records.map((rec) => ({
    receipt_id: rec.receipt_id,
    scope: rec.scope,
    ...verifyReceipt(rec.payload, vopts),
    scope_hygiene: checkScopeHygiene(rec.payload),
  }));

  // Tenant cross-scope re-derivation where both scopes exist.
  const tenantChecks = [];
  for (const [rid, scopes] of byId) {
    if (scopes.internal && scopes.external) {
      tenantChecks.push({ receipt_id: rid, ...checkTenantPair(scopes.internal, scopes.external) });
    }
  }

  const verified = results.filter((r) => r.status === 'VERIFIED');
  const failed = results.filter((r) => r.status !== 'VERIFIED');

  // Internal-scope sweep is the canonical 198 -> 195/3 count.
  const internal = results.filter((r) => r.scope === 'internal');
  const internalVerified = internal.filter((r) => r.status === 'VERIFIED');
  const internalFailed = internal.filter((r) => r.status !== 'VERIFIED');

  // Chains present in the corpus.
  const { chains } = groupChains(records);
  const chainReport = [];
  for (const { scope, loop_id, payloads } of chains.values()) {
    chainReport.push({ scope, loop_id, ...verifyChain(payloads, vopts) });
  }

  // Expectation check: the documented by-design failures must be exactly the
  // internal failures, and everything else must verify.
  const expectedFailIds = new Set(Object.keys(BY_DESIGN_FAILURES));
  const failedIds = new Set(internalFailed.map((r) => r.receipt_id));
  const unexpectedFailures = internalFailed.filter((r) => !expectedFailIds.has(r.receipt_id));
  const missingExpected = [...expectedFailIds].filter((id) => !failedIds.has(id));
  const tenantOK = tenantChecks.every((t) => t.ok);
  const chainsOK = chainReport.every((c) => c.status === 'VERIFIED');
  const expectationMet =
    unexpectedFailures.length === 0 && missingExpected.length === 0 && tenantOK && chainsOK;

  if (opts.json) {
    console.log(JSON.stringify({
      mode: 'corpus',
      totals: { records: results.length, internal: internal.length, internal_verified: internalVerified.length, internal_failed: internalFailed.length },
      results, tenantChecks, chains: chainReport,
      expectation: { unexpectedFailures: unexpectedFailures.map((r) => r.receipt_id), missingExpected, tenantOK, chainsOK, expectationMet },
    }, null, 2));
    process.exit(expectationMet ? 0 : 1);
  }

  console.log('=== LYHNA CORPUS SWEEP ===\n');
  if (!opts.quiet) {
    console.log(`internal scope (${internal.length} receipts):`);
    for (const r of internal) printReceiptLine(r);
    const external = results.filter((r) => r.scope === 'external');
    if (external.length) {
      console.log(`\nexternal scope (${external.length} receipts):`);
      for (const r of external) printReceiptLine(r);
    }
  }

  console.log('\n--- by-design failures (must fail by math) ---');
  for (const r of internalFailed) {
    const note = BY_DESIGN_FAILURES[r.receipt_id] || '!!! UNEXPECTED FAILURE !!!';
    console.log(`  ${styleStatus(r.status)} ${r.receipt_id}  ${r.reason}\n      -> ${note}`);
  }

  console.log('\n--- chains ---');
  for (const c of chainReport) {
    console.log(`  ${styleStatus(c.status)} loop ${c.loop_id} scope=${c.scope} links=${c.length} ` +
      `sealed=${c.sealed} action_count ${c.declared_action_count}==${c.in_loop_links} goal_hash_consistent=${c.goal_hash_consistent}`);
  }

  console.log('\n--- tenant_hash re-derivation (sha256(tenant_id)) ---');
  console.log(`  ${tenantChecks.length} cross-scope pair(s), all match: ${tenantOK}`);

  console.log('\n=== SUMMARY ===');
  console.log(`  internal: ${internalVerified.length} VERIFIED / ${internalFailed.length} FAILED (of ${internal.length})`);
  console.log(`  all records: ${verified.length} VERIFIED / ${failed.length} FAILED (of ${results.length})`);
  console.log(`  chains: ${chainReport.filter((c) => c.status === 'VERIFIED').length}/${chainReport.length} verified`);
  if (unexpectedFailures.length) console.log(`  !!! UNEXPECTED FAILURES: ${unexpectedFailures.map((r) => r.receipt_id).join(', ')}`);
  if (missingExpected.length) console.log(`  !!! EXPECTED-FAIL RECEIPTS THAT VERIFIED (verifier too permissive): ${missingExpected.join(', ')}`);
  console.log(`\n  EXPECTATION ${expectationMet ? 'MET — 195 verify / 3 fail-by-design reproduced, chains cold-verified.' : 'NOT MET.'}`);

  process.exit(expectationMet ? 0 : 1);
}

main();
