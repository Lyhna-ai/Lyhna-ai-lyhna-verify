// The single trust root for the live Lyhna corpus.
//
// Raw 32-byte Ed25519 public key (hex). This is the ONLY thing the verifier
// trusts. Override at the CLI with --pubkey for a different signer.
export const LYHNA_PUBLIC_KEY_HEX =
  '2ecb73042161b7b0008971499b191ec9e3824cd4a6e058a8cede90b04e1efff2';

// The three receipts that are SUPPOSED to fail, with their documented cause.
// This map is used for REPORTING ONLY — it never influences a verdict. The
// verifier rejects these by math; this is just the human-readable annotation.
export const BY_DESIGN_FAILURES = {
  lrv2_1780276647983_6f9c7ad3: 'permanent SIGNATURE_INVALID defect receipt (Phase 1; exists to be invalid)',
  lrv2_1780280969194_d02c6928: 'pre-standardization resolution receipt (transitional signing basis)',
  lrv2_1780354143186_7fe5f993: 'pre-standardization resolution receipt (transitional signing basis)',
};
