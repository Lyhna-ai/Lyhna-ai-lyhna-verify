// Tenant binding checks.
//
// `tenant_hash` is RE-DERIVED as sha256(tenant_id) and never trusted from the
// receipt. Scope separation is enforced: the internal scope carries `tenant_id`
// only; the external scope carries `tenant_hash` only.

import { sha256Hex } from './ed25519.mjs';

export function deriveTenantHash(tenantId) {
  return sha256Hex(String(tenantId));
}

// Check a single payload's scope hygiene. Returns {scope, ok, reason}.
export function checkScopeHygiene(payload) {
  const hasId = Object.prototype.hasOwnProperty.call(payload, 'tenant_id');
  const hasHash = Object.prototype.hasOwnProperty.call(payload, 'tenant_hash');
  if (hasId && !hasHash) return { scope: 'internal', ok: true, reason: 'OK' };
  if (hasHash && !hasId) return { scope: 'external', ok: true, reason: 'OK' };
  if (hasId && hasHash) return { scope: 'mixed', ok: false, reason: 'SCOPE_LEAK_BOTH_PRESENT' };
  return { scope: 'unknown', ok: false, reason: 'NO_TENANT_BINDING' };
}

// Cross-scope tenant check: given the internal payload (with tenant_id) and the
// external payload (with tenant_hash) for the same receipt, re-derive and compare.
export function checkTenantPair(internalPayload, externalPayload) {
  const derived = deriveTenantHash(internalPayload.tenant_id);
  const ok = derived === externalPayload.tenant_hash;
  return { ok, derived, claimed: externalPayload.tenant_hash };
}
