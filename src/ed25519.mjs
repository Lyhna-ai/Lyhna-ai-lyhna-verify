// Independent Ed25519 + hashing primitives, built only on Node's `crypto`
// (OpenSSL). No third-party crypto, no project imports.
//
// Encoding normalization is deliberately permissive on the INPUT side only:
// signatures and public keys may arrive as base64, base64url, hex, or with an
// `ed25519:` prefix. The verification math is not permissive — exactly one
// signature check is performed per receipt by the caller.

import crypto from 'node:crypto';

// SPKI DER header for an Ed25519 public key, followed by the 32 raw key bytes.
const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function stripPrefix(s) {
  s = String(s).trim();
  if (s.startsWith('ed25519:')) s = s.slice('ed25519:'.length);
  return s;
}

// Lenient base64 / base64url decode. Returns a Buffer or null.
function tryBase64(s) {
  const norm = s.replace(/-/g, '+').replace(/_/g, '/');
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(norm)) return null;
  const buf = Buffer.from(norm, 'base64');
  return buf.length ? buf : null;
}

function rawToKeyObject(raw32) {
  if (raw32.length !== 32) throw new Error(`ed25519 raw key must be 32 bytes, got ${raw32.length}`);
  const der = Buffer.concat([SPKI_ED25519_PREFIX, raw32]);
  return crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
}

// Returns the canonical 32-byte raw public key as lowercase hex, regardless of
// the input encoding. Used for pinning/comparison against a trusted key.
export function rawPublicKeyHex(input) {
  if (Buffer.isBuffer(input)) return input.subarray(input.length - 32).toString('hex');
  const s = stripPrefix(input);
  if (/^[0-9a-fA-F]{64}$/.test(s)) return s.toLowerCase();
  const b = tryBase64(s);
  if (b && b.length === 32) return b.toString('hex');
  // Fall back to importing and extracting the trailing 32 bytes of the SPKI DER.
  const key = normalizePublicKey(input);
  const der = key.export({ format: 'der', type: 'spki' });
  return Buffer.from(der.subarray(der.length - 32)).toString('hex');
}

// Returns a Node KeyObject for the public key in any supported encoding.
export function normalizePublicKey(input) {
  if (Buffer.isBuffer(input)) return rawToKeyObject(input);
  const s = stripPrefix(input);
  if (/^[0-9a-fA-F]{64}$/.test(s)) return rawToKeyObject(Buffer.from(s, 'hex'));
  if (s.includes('BEGIN PUBLIC KEY')) return crypto.createPublicKey(s);
  const b = tryBase64(s);
  if (b && b.length === 32) return rawToKeyObject(b);
  if (b && b.length === 44) return crypto.createPublicKey({ key: b, format: 'der', type: 'spki' });
  throw new Error('unrecognized public key encoding');
}

// Returns a 64-byte signature Buffer from any supported encoding.
export function normalizeSignature(input) {
  if (Buffer.isBuffer(input)) return input;
  const s = stripPrefix(input);
  if (/^[0-9a-fA-F]{128}$/.test(s)) return Buffer.from(s, 'hex');
  const b = tryBase64(s);
  if (b) return b;
  throw new Error('unrecognized signature encoding');
}

export function verifyEd25519(message, signature, publicKey) {
  // Ed25519 takes a null algorithm in Node's one-shot verify.
  return crypto.verify(null, message, publicKey, signature);
}

export function sha256Hex(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(input, 'utf8');
  return crypto.createHash('sha256').update(buf).digest('hex');
}
