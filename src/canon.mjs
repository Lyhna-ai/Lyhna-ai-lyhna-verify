// Independent, from-scratch canonicalization.
//
// Recursive sorted-key serialization, no whitespace, JSON.stringify for scalars.
// This is a deliberate re-implementation of the Lyhna signer's canonical form.
// It does NOT import @lyhna/bind, lyhna-core, or the proxy verifier — that
// independence IS the proof. The only thing this must agree with is the math.
//
// Determinism notes:
//  - object keys are sorted lexicographically by UTF-16 code unit (Array#sort default),
//    which matches the signer's `Object.keys(v).sort()`.
//  - arrays preserve order (order is semantically significant).
//  - scalars (string/number/boolean) are emitted via JSON.stringify.
//  - null is emitted literally as `null`.
export function canon(value) {
  if (value === null) return 'null';
  if (Array.isArray(value)) {
    return '[' + value.map(canon).join(',') + ']';
  }
  if (typeof value === 'object') {
    return (
      '{' +
      Object.keys(value)
        .sort()
        .map((k) => JSON.stringify(k) + ':' + canon(value[k]))
        .join(',') +
      '}'
    );
  }
  return JSON.stringify(value);
}
