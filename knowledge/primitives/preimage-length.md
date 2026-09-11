# Preimage-length integer

Authenticates a SHA-256 preimage and returns its byte length minus a public
offset as a small integer.

- **Position:** extremely small locking fragment when variable witness length
  is an acceptable integer encoding.
- **Evidence:** locally reproduced with offset, wrong-preimage, short-input, and
  both offset-edge failures.
- **Representative result:** offset 0 uses a 42-byte script and a 2-byte
  serialized empty witness; offset 520 uses a 46-byte script and a 524-byte
  serialized maximum-size witness. Both peak at three stack items.
- **Security:** binding is inherited from SHA-256; hiding depends on unpredictable
  preimage bytes and leaks the length when opened.
- **Limitation:** the value range is coupled to Bitcoin's 520-byte item limit.
  Offset 0 admits an empty preimage; offset 520 admits only a 520-byte item.

See the [implementation README](../../src/commitments/README.md) and catalog
record `commitment/preimage-length`.
