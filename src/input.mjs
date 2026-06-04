// Input loading & normalization.
//
// Accepts, and auto-detects between:
//   - a single receipt (a JSON object carrying `signature`)
//   - a corpus / chain as NDJSON, where each line is either a bare receipt
//     payload OR a wrapper `{ receipt_id, scope, payload }` (the export shape)
//   - a JSON array of receipt payloads (or wrapper objects)
//   - a seed-style bundle `{ head_internal, head_external, close_internal, ... }`
//
// Every loaded receipt is normalized to a record:
//   { receipt_id, scope, payload }
// where scope is 'internal' | 'external' | 'unknown'.

import { readFileSync } from 'node:fs';

function inferScope(payload) {
  const hasId = payload && Object.prototype.hasOwnProperty.call(payload, 'tenant_id');
  const hasHash = payload && Object.prototype.hasOwnProperty.call(payload, 'tenant_hash');
  if (hasId && !hasHash) return 'internal';
  if (hasHash && !hasId) return 'external';
  return 'unknown';
}

function toRecord(obj, fallbackScope) {
  // Wrapper shape from the export: { receipt_id, scope, payload }
  if (obj && obj.payload && typeof obj.payload === 'object' && obj.payload.signature) {
    return {
      receipt_id: obj.receipt_id ?? obj.payload.receipt_id ?? null,
      scope: obj.scope ?? inferScope(obj.payload),
      payload: obj.payload,
    };
  }
  // Bare receipt payload.
  return {
    receipt_id: obj.receipt_id ?? null,
    scope: fallbackScope ?? inferScope(obj),
    payload: obj,
  };
}

function isReceiptLike(obj) {
  return obj && typeof obj === 'object' && (obj.signature || (obj.payload && obj.payload.signature));
}

// Parse already-loaded text/JSON into records.
export function parseRecords(text) {
  const trimmed = text.trim();
  const records = [];

  // Try whole-document JSON first (array, single object, or seed bundle).
  let asJson;
  try {
    asJson = JSON.parse(trimmed);
  } catch {
    asJson = undefined;
  }

  if (asJson !== undefined) {
    if (Array.isArray(asJson)) {
      for (const o of asJson) records.push(toRecord(o));
      return records;
    }
    if (isReceiptLike(asJson)) {
      return [toRecord(asJson)];
    }
    // Seed-style bundle: values are receipt payloads keyed by name; the key's
    // suffix (_internal/_external) hints the scope.
    if (asJson && typeof asJson === 'object') {
      for (const [k, v] of Object.entries(asJson)) {
        if (!v || typeof v !== 'object') continue;
        const scope = /external/i.test(k) ? 'external' : /internal/i.test(k) ? 'internal' : undefined;
        records.push(toRecord(v, scope));
      }
      if (records.length) return records;
    }
  }

  // Fall back to NDJSON.
  for (const line of trimmed.split('\n')) {
    const l = line.trim();
    if (!l) continue;
    records.push(toRecord(JSON.parse(l)));
  }
  return records;
}

export function loadRecords(path) {
  return parseRecords(readFileSync(path, 'utf8'));
}

// Group records into loop chains keyed by `${scope}::${loop_id}`. Records with
// no constraints.loop are not part of any chain and are returned separately.
export function groupChains(records) {
  const chains = new Map();
  const standalone = [];
  for (const rec of records) {
    const loop = rec.payload && rec.payload.constraints && rec.payload.constraints.loop;
    if (loop && loop.loop_id != null) {
      const key = `${rec.scope}::${loop.loop_id}`;
      if (!chains.has(key)) chains.set(key, { scope: rec.scope, loop_id: loop.loop_id, payloads: [] });
      chains.get(key).payloads.push(rec.payload);
    } else {
      standalone.push(rec);
    }
  }
  return { chains, standalone };
}
