#!/usr/bin/env python3
"""Independent zlib result vectors. No Script implementation is called here."""
import json
import zlib

def vectors():
    inputs = [b"", b"123456789", bytes([1, 2, 1]), bytes([2, 0, 2])]
    inputs += [bytes([x]) for x in range(256)]
    inputs += [bytes([x, (173 * x + 19) % 256]) for x in range(256)]
    for n in [2, 3, 4, 9, 32, 128, 257, 512, 728, 808, 809, 995, 997]:
        inputs += [bytes([255]) * n, bytes(n), bytes((173 * i + 19) % 256 for i in range(n))]
    return [{"hex": v.hex(), "packed": zlib.adler32(v),
             "state": [zlib.adler32(v) & 65535, zlib.adler32(v) >> 16]} for v in inputs]

if __name__ == "__main__":
    print(json.dumps({"reference": "Python zlib.adler32, default initial state 1",
                      "generator": "oracle.py", "vectors": vectors()}, indent=2))
