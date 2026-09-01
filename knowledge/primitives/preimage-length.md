# Preimage-length integer

Authenticates a SHA-256 preimage and returns its byte length minus a public
offset as a small integer.

- **Position:** extremely small locking fragment when variable witness length
  is an acceptable integer encoding.
- **Evidence:** locally reproduced with offset, wrong-preimage, and short-input
  failures.
- **Representative result:** default offset 16 uses a 44-byte script, 18–524
  witness bytes, and three stack items.
- **Security:** binding is inherited from SHA-256; hiding depends on unpredictable
  preimage bytes and leaks the length when opened.
- **Limitation:** the value range is coupled to Bitcoin's 520-byte item limit.

See the [implementation README](../../src/commitments/README.md) and catalog
record `commitment/preimage-length`.
