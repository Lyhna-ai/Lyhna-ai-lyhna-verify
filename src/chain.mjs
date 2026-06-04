// Loop-chain verification.
//
// Walks an arbitrary-length chain:
//   head (constraints.loop.prior_receipt_id === null)
//     -> N in-loop links (each prior_receipt_id resolves to its predecessor)
//       -> exactly one terminal loop_close (action_type === 'loop_close',
//          carrying both constraints.loop and constraints.loop_close)
//
// Invariants checked:
//   - single head, single terminal close, close is last
//   - prior_receipt_id continuity with no cycles and no orphans
//   - constant loop_id across every constraints.loop / constraints.loop_close
//   - consistent goal_hash across every occurrence (consistency ONLY — the
//     plaintext goal is never demanded; the corpus is content-blind)
//   - loop_close.constraints.loop_close.action_count === in-loop link count
//     (NOT hardcoded to 1)
//   - reject unsealed: in-loop links present but no terminal close
//   - every receipt individually VERIFIED (sig/hash)
//
// action_count semantics: every receipt that is not the terminal close is an
// in-loop action link (the head is action #1). So action_count must equal
// (chain length - 1).

import { verifyReceipt } from './receipt.mjs';

function loopOf(p) {
  return (p.constraints && p.constraints.loop) || null;
}
function closeOf(p) {
  return (p.constraints && p.constraints.loop_close) || null;
}

/**
 * @param {object[]} payloads  receipts belonging to ONE scope of ONE loop.
 * @param {object} [opts]  passed through to verifyReceipt (e.g. trustedKeyHex).
 */
export function verifyChain(payloads, opts = {}) {
  const result = {
    length: payloads.length,
    loop_id: null,
    sealed: false,
    ordered: false,
    continuity_ok: false,
    loop_id_consistent: false,
    goal_hash_consistent: false,
    goal_hash: null,
    action_count_ok: false,
    declared_action_count: null,
    in_loop_links: null,
    all_receipts_verified: false,
    receipts: [],
    status: 'FAILED',
    reasons: [],
  };
  const fail = (r) => {
    result.reasons.push(r);
    return result;
  };

  if (!Array.isArray(payloads) || payloads.length === 0) return fail('EMPTY_CHAIN');

  // Verify every receipt cryptographically first.
  const verified = payloads.map((p) => verifyReceipt(p, opts));
  result.receipts = verified.map((v) => ({
    receipt_id: v.receipt_id,
    action_type: v.action_type,
    status: v.status,
    reason: v.reason,
  }));
  result.all_receipts_verified = verified.every((v) => v.status === 'VERIFIED');
  if (!result.all_receipts_verified) fail('RECEIPT_SIGNATURE_OR_HASH_FAILED');

  // Index by id and by prior pointer.
  const byId = new Map();
  for (const p of payloads) byId.set(p.receipt_id, p);
  const byPrior = new Map();
  const heads = [];
  const closes = [];
  for (const p of payloads) {
    const loop = loopOf(p);
    if (!loop || !Object.prototype.hasOwnProperty.call(loop, 'prior_receipt_id')) {
      return fail('LINK_MISSING_constraints.loop');
    }
    if (loop.prior_receipt_id === null) heads.push(p);
    else byPrior.set(loop.prior_receipt_id, p);
    if (p.action_type === 'loop_close') closes.push(p);
  }

  if (heads.length !== 1) fail(`EXPECTED_1_HEAD_GOT_${heads.length}`);
  if (closes.length !== 1) fail(`EXPECTED_1_CLOSE_GOT_${closes.length}`);
  if (heads.length !== 1 || closes.length !== 1) return result;

  const head = heads[0];
  const close = closes[0];
  if (head.action_type === 'loop_close') fail('HEAD_IS_A_CLOSE');

  // Walk the chain by prior pointers.
  const sequence = [head];
  const seen = new Set([head.receipt_id]);
  let cur = head;
  while (true) {
    const next = byPrior.get(cur.receipt_id);
    if (!next) break;
    if (seen.has(next.receipt_id)) {
      fail('CYCLE_DETECTED');
      break;
    }
    sequence.push(next);
    seen.add(next.receipt_id);
    cur = next;
  }

  // Continuity: every receipt must be consumed, no orphans.
  result.continuity_ok = sequence.length === payloads.length;
  if (!result.continuity_ok) fail('BROKEN_CONTINUITY_OR_ORPHAN_LINKS');

  // Sealed: the terminal link must be the (only) loop_close.
  const terminal = sequence[sequence.length - 1];
  result.sealed = terminal.action_type === 'loop_close' && terminal.receipt_id === close.receipt_id;
  if (!result.sealed) fail('UNSEALED_OR_NONTERMINAL_CLOSE');

  // A close must carry both constraints.loop and constraints.loop_close.
  if (!loopOf(close) || !closeOf(close)) fail('CLOSE_MISSING_loop_OR_loop_close');

  result.ordered = result.continuity_ok && result.sealed;

  // loop_id consistency across every loop and loop_close block.
  const loopIds = new Set();
  for (const p of payloads) {
    const l = loopOf(p);
    if (l && l.loop_id != null) loopIds.add(l.loop_id);
    const c = closeOf(p);
    if (c && c.loop_id != null) loopIds.add(c.loop_id);
  }
  result.loop_id = loopIds.size === 1 ? [...loopIds][0] : null;
  result.loop_id_consistent = loopIds.size === 1;
  if (!result.loop_id_consistent) fail(`INCONSISTENT_loop_id_${loopIds.size}_DISTINCT`);

  // goal_hash consistency across every occurrence (consistency only).
  const goalHashes = new Set();
  for (const p of payloads) {
    const l = loopOf(p);
    if (l && l.goal_hash != null) goalHashes.add(l.goal_hash);
    const c = closeOf(p);
    if (c && c.goal_hash != null) goalHashes.add(c.goal_hash);
  }
  result.goal_hash = goalHashes.size === 1 ? [...goalHashes][0] : null;
  result.goal_hash_consistent = goalHashes.size === 1;
  if (!result.goal_hash_consistent) fail(`INCONSISTENT_goal_hash_${goalHashes.size}_DISTINCT`);

  // action_count == in-loop link count (chain length minus the terminal close).
  const inLoopLinks = sequence.length - 1;
  result.in_loop_links = inLoopLinks;
  const declared = closeOf(close) ? closeOf(close).action_count : null;
  result.declared_action_count = declared;
  result.action_count_ok = declared === inLoopLinks;
  if (!result.action_count_ok) fail(`action_count_${declared}_NE_links_${inLoopLinks}`);

  // Verdict is FAILED if ANY invariant recorded a reason. Basing this on the
  // accumulated reasons (rather than re-listing booleans) ensures that hard
  // failures which are not mirrored in a boolean flag — e.g. HEAD_IS_A_CLOSE
  // for a lone, validly-signed loop_close with prior_receipt_id: null — are not
  // silently overwritten with OK.
  result.status = result.reasons.length === 0 ? 'VERIFIED' : 'FAILED';
  if (result.status === 'VERIFIED') result.reasons = ['OK'];
  return result;
}
