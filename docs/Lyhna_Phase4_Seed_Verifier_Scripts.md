# Lyhna — Phase 4 Seed Verifier Scripts

**Date:** 2026-06-03
**Purpose:** The independent cold-verification scripts written at Phase 3 closure. These are the
**seed** for the Phase 4 hardened verifier — start from these, do not start from zero.
**Companions:** `Lyhna_Session_Handoff_Phase3_Closure.md`, `Lyhna_Phase4_Plus_Roadmap_and_Charter.md`.

## What these are and are not

These three scripts independently verified the production corpus at Phase 3 closure, using a
**from-scratch canonicalizer + Node `crypto` (OpenSSL) Ed25519** — deliberately NOT the project's
`@noble`-based verifier. That independence is the whole point: a verifier that re-implements the math
and reaches the same answer proves "trusts no one."

They are a SEED, not the finished Phase 4 artifact. Known limitation to fix in Phase 4: the corpus has
multiple signing shapes (standard / no-`canonical_hash` resolution / pre-standardization). `verify_all.mjs`
below assumes every receipt has a `canonical_hash` field, so it wrongly "fails" the 11 no-`canonical_hash`
resolution receipts; `verify_resolution.mjs` shows how those actually verify. The Phase 4 verifier must
**detect the receipt shape and apply the correct scheme per shape**, and must correctly REJECT the
by-design failures (the SIGNATURE_INVALID defect receipt + the 2 pre-standardization receipts). An
"all green" verifier is WRONG.

## Key facts the scripts encode (for re-derivation)

- **Public key:** `2ecb73042161b7b0008971499b191ec9e3824cd4a6e058a8cede90b04e1efff2` (raw 32-byte ed25519, hex).
- **SPKI DER prefix (Node):** `302a300506032b6570032100` + raw key bytes → import as SPKI DER.
- **Canonicalization:** recursive sorted-key, no whitespace, `JSON.stringify` for scalars.
- **Standard receipt:** has `canonical_hash`; `core` = receipt minus `{signature, public_key, canonical_hash}`;
  `canonical_hash == sha256(canon(core))`; signature = Ed25519 over the **hex string** of `canonical_hash`.
- **`authority_resolution` (newer) receipt:** NO `canonical_hash`; `core` = receipt minus
  `{signature, public_key}`; signature = Ed25519 over hex of `sha256(canon(core))`.
- **`tenant_hash`** = `sha256(tenant_id)` — re-derive, do not trust.
- **`goal_hash`** = `sha256(utf8(goal))` hex, no normalization; consistent across `constraints.loop` and
  `constraints.loop_close`, both scopes.
- **Corpus result to reproduce:** 195 verify / 3 fail-by-design out of 198.
- **By-design failures:** `lrv2_1780276647983_6f9c7ad3` (permanent SIGNATURE_INVALID defect),
  `lrv2_1780280969194_d02c6928`, `lrv2_1780354143186_7fe5f993` (pre-standardization resolution).
- **Data source:** Supabase `nstchtapastyzxngcgjf`, table `receipts`, columns `receipt_payload`
  (internal) / `external_receipt_payload`. Tenant `tenant_d04579fbbb4a`.

---

## Script 1 — single-chain verifier (`verify.mjs`)

Verifies a loop chain (head + close, internal + external scopes). Standard-receipt scheme.

```javascript
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';

const R = JSON.parse(readFileSync('./receipts.json','utf8')); // {head_internal, head_external, close_internal, close_external}
const ENVELOPE = new Set(['signature','public_key','canonical_hash']);

// Independent recursive sorted-key canonicalization, no whitespace. NOT the project's canonicalizer.
function canon(v){
  if (v===null) return 'null';
  if (Array.isArray(v)) return '['+v.map(canon).join(',')+']';
  if (typeof v==='object'){
    return '{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canon(v[k])).join(',')+'}';
  }
  return JSON.stringify(v);
}
function coreOf(receipt){
  const core={}; for (const k of Object.keys(receipt)) if(!ENVELOPE.has(k)) core[k]=receipt[k]; return core;
}
function spkiFromRawHex(hex){
  const der = Buffer.concat([Buffer.from('302a300506032b6570032100','hex'), Buffer.from(hex,'hex')]);
  return crypto.createPublicKey({key:der,format:'der',type:'spki'});
}
function verifyOne(name, r){
  const recomputed = crypto.createHash('sha256').update(canon(coreOf(r)),'utf8').digest('hex');
  const hashOK = recomputed === r.canonical_hash;
  const key = spkiFromRawHex(r.public_key);
  const sig = Buffer.from(r.signature,'base64');
  const sigOK = crypto.verify(null, Buffer.from(r.canonical_hash,'utf8'), key, sig); // sig over HEX STRING of canonical_hash
  return {name, hashOK, recomputed, stored:r.canonical_hash, sigOK};
}

console.log('=== CANONICAL-HASH RECONSTRUCT + ED25519 SIG ===');
let allHash=true, allSig=true;
for (const [name,r] of Object.entries(R)){
  const v=verifyOne(name,r); allHash=allHash&&v.hashOK; allSig=allSig&&v.sigOK;
  console.log(`${name.padEnd(16)} hash ${v.hashOK?'OK ':'FAIL'}  sig ${v.sigOK?'OK ':'FAIL'}`);
}
const th = crypto.createHash('sha256').update(R.head_internal.tenant_id,'utf8').digest('hex');
const thOK = th === R.head_external.tenant_hash;
console.log(`tenant_hash sha256(tenant_id) match: ${thOK?'OK':'FAIL'}`);
const goals = new Set([
  R.head_internal.constraints.loop.goal_hash, R.head_external.constraints.loop.goal_hash,
  R.close_internal.constraints.loop.goal_hash, R.close_external.constraints.loop.goal_hash,
  R.close_internal.constraints.loop_close.goal_hash, R.close_external.constraints.loop_close.goal_hash,
]);
console.log(`goal_hash consistent across chain (expect 1): ${goals.size}`);
// chain integrity
function chain(head, close){
  return head.constraints.loop.prior_receipt_id === null
    && close.constraints.loop.prior_receipt_id === head.receipt_id
    && close.constraints.loop_close.action_count === 1
    && close.action_type === 'loop_close'
    && head.action_type !== 'loop_close'
    && head.constraints.loop.loop_id === close.constraints.loop.loop_id;
}
const ci = chain(R.head_internal, R.close_internal);
const ce = chain(R.head_external, R.close_external);
const scope = ('tenant_id' in R.head_internal) && !('tenant_hash' in R.head_internal)
           && ('tenant_hash' in R.head_external) && !('tenant_id' in R.head_external);
console.log(`chain internal:${ci} external:${ce} scope-sep:${scope}`);
console.log((allHash&&allSig&&thOK&&goals.size===1&&ci&&ce&&scope)
  ? 'CHAIN VERIFIES COLD ON BOTH SCOPES — trusts no one.' : 'VERIFICATION FAILED.');
```

---

## Script 2 — full-corpus sweep (`verify_all.mjs`)

Processes an NDJSON dump of all internal payloads. **Has the known bug** (assumes every receipt has
`canonical_hash`); kept as-is so Phase 4 learns from it. Reproduces 187/11 split before the resolution
fix in Script 3 is folded in.

```javascript
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';

const lines = readFileSync('./all_payloads.ndjson','utf8').split('\n').filter(l=>l.trim());
const ENVELOPE = new Set(['signature','public_key','canonical_hash']);
function canon(v){
  if (v===null) return 'null';
  if (Array.isArray(v)) return '['+v.map(canon).join(',')+']';
  if (typeof v==='object') return '{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canon(v[k])).join(',')+'}';
  return JSON.stringify(v);
}
function coreOf(r){ const c={}; for(const k of Object.keys(r)) if(!ENVELOPE.has(k)) c[k]=r[k]; return c; }
function spki(hex){ return crypto.createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),Buffer.from(hex,'hex')]),format:'der',type:'spki'}); }

let hashOK=0,hashFAIL=0,sigOK=0,sigFAIL=0; const keys=new Set(); const failures=[];
const outcomes={}, tiers={};
for (const line of lines){
  const r=JSON.parse(line);
  outcomes[r.outcome]=(outcomes[r.outcome]||0)+1; tiers[r.authority_tier]=(tiers[r.authority_tier]||0)+1;
  if(r.public_key) keys.add(r.public_key);
  const recomputed = crypto.createHash('sha256').update(canon(coreOf(r)),'utf8').digest('hex');
  if(recomputed===r.canonical_hash) hashOK++; else { hashFAIL++; failures.push({id:r.receipt_id,why:'hash',action:r.action_type}); }
  if(!r.signature||!r.public_key) continue;
  let sOK=false; try{ sOK=crypto.verify(null,Buffer.from(r.canonical_hash,'utf8'),spki(r.public_key),Buffer.from(r.signature,'base64')); }catch{}
  if(sOK) sigOK++; else { sigFAIL++; failures.push({id:r.receipt_id,why:'sig',action:r.action_type}); }
}
console.log(`hash: ${hashOK} OK / ${hashFAIL} FAIL`);
console.log(`sig:  ${sigOK} OK / ${sigFAIL} FAIL`);
console.log(`keys: ${keys.size}`, [...keys].map(k=>k.slice(0,16)+'…'));
console.log('outcomes:', outcomes, 'tiers:', tiers);
for(const f of failures) console.log(JSON.stringify(f));
// NOTE: the 11 "failures" here that are authority_resolution receipts are NOT real failures —
// they have no canonical_hash field and use Script 3's scheme. Phase 4 must shape-detect.
```

---

## Script 3 — resolution-shape verifier (`verify_resolution.mjs`)

Shows how the no-`canonical_hash` `authority_resolution` receipts actually verify, and isolates the
3 by-design failures. The Phase 4 verifier merges this scheme-detection into a single shape-aware pass.

```javascript
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
const lines = readFileSync('./all_payloads.ndjson','utf8').split('\n').filter(l=>l.trim());
function canon(v){
  if (v===null) return 'null';
  if (Array.isArray(v)) return '['+v.map(canon).join(',')+']';
  if (typeof v==='object') return '{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canon(v[k])).join(',')+'}';
  return JSON.stringify(v);
}
function spki(hex){ return crypto.createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),Buffer.from(hex,'hex')]),format:'der',type:'spki'}); }

const res = lines.map(l=>JSON.parse(l)).filter(r=>r.action_type==='authority_resolution');
const ENV=new Set(['signature','public_key']); // NOTE: do NOT strip canonical_hash for this shape
let verified=0; const fails=[];
for(const r of res){
  const core={}; for(const k of Object.keys(r)) if(!ENV.has(k)) core[k]=r[k];
  const h=crypto.createHash('sha256').update(canon(core),'utf8').digest('hex');
  const ok = crypto.verify(null, Buffer.from(h,'utf8'), spki(r.public_key), Buffer.from(r.signature,'base64'));
  if(ok) verified++; else fails.push(r.receipt_id);
}
console.log(`authority_resolution: ${verified}/${res.length} verify under hex(sha256(core)) scheme`);
console.log('by-design failures (must remain failing):', fails);
// Expected: the newer resolution receipts verify; the pre-standardization ones do not (correct).
```

---

## How Phase 4 uses these

1. **Merge** the three schemes into one shape-aware verifier: detect whether a receipt has
   `canonical_hash` (standard) or not (resolution scheme), strip the correct envelope, verify accordingly.
2. **Preserve** the rejection behavior: the SIGNATURE_INVALID defect receipt and the 2 pre-standardization
   receipts MUST fail. Output should state WHY each fails, not just that it does.
3. **Package** as a standalone module depending only on a crypto lib + the public key — no project imports.
4. **Reproduce** 195 verify / 3 fail-by-design against the live corpus export as the exit-condition test.
5. **Independence is the proof** — re-implement, do not import `@lyhna/bind` or the proxy verifier.
```
