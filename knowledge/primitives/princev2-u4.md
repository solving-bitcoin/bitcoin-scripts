# PRINCEv2 over u4 digits

Implements the lightweight PRINCEv2 block cipher with an embedded key and
nibble-oriented plaintext.

- **Position:** substantially smaller local block-cipher fragment than AES-128,
  with a different standardization and security context.
- **Evidence:** differentially validated against a native reference and known
  vectors.
- **Representative result:** 7,685 script bytes and 17–33 witness bytes.
- **Tradeoff:** use is justified only where PRINCEv2 is an acceptable protocol
  primitive; size alone does not make it interchangeable with AES.
- **Deployment:** large research fragment with composition-dependent limits.

See the [implementation README](../../src/ciphers/prince/README.md) and catalog
record `cipher/princev2-u4`.
