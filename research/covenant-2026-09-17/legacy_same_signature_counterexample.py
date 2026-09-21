#!/usr/bin/env python3
"""Deterministic ECDSA counterexample; no Bitcoin Script executor is claimed.

The fixed raw legacy boundary vector is 6eadabac:
    OP_2DUP OP_CHECKSIGVERIFY OP_CODESEPARATOR OP_CHECKSIG
It accepts the same free signature/key for two distinct ALL digests.  We check
the curve equations locally and, when requested, independently with OpenSSL.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
SCRIPT = bytes.fromhex("6eadabac")


def add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    x, y = a
    u, v = b
    if x == u and (y + v) % P == 0:
        return None
    slope = ((3 * x * x) * pow(2 * y, -1, P) if a == b
             else (v - y) * pow(u - x, -1, P)) % P
    nx = (slope * slope - x - u) % P
    return nx, (slope * (x - nx) - y) % P


def mul(k, a=G):
    result = None
    k %= N
    while k:
        if k & 1:
            result = add(result, a)
        a = add(a, a)
        k >>= 1
    return result


def hash256(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def vector(data):
    assert len(data) < 253
    return bytes([len(data)]) + data


def tx(script_sig, output_script, *, outpoint_txid="42" * 32,
       outpoint_vout=0, output_value=990000):
    # The default is synthetic; callers may supply an actual funded outpoint.
    return (struct.pack("<I", 2) + b"\x01" + bytes.fromhex(outpoint_txid)[::-1]
            + struct.pack("<I", outpoint_vout)
            + vector(script_sig) + b"\xff" * 4 + b"\x01"
            + struct.pack("<Q", output_value) + vector(output_script) + b"\0" * 4)


def signature_integer(x):
    data = x.to_bytes((x.bit_length() + 7) // 8, "big")
    if data[0] & 128:
        data = b"\0" + data
    return b"\x02" + vector(data)


def verify(z, r, s, q):
    point = add(mul(z * pow(s, -1, N)), mul(r * pow(s, -1, N), q))
    return point is not None and point[0] % N == r, point


def make_vector(name, output_script, *, outpoint_txid="42" * 32,
                outpoint_vout=0, output_value=990000, p2sh=False):
    """Create and independently verify a pair for a synthetic or real outpoint.

    outpoint_txid is normal displayed txid hex, not wire-order bytes. With
    p2sh=True the spent output must be HASH160(SCRIPT) P2SH; the unlocking
    script then includes the four-byte redeem script automatically.
    """
    tx_params = {"outpoint_txid": outpoint_txid, "outpoint_vout": outpoint_vout,
                 "output_value": output_value}
    # Core legacy removes all OP_CODESEPARATORs from the active suffix.
    # The free signature does not occur in either fixed scriptCode.
    codes = [bytes.fromhex("6eadac"), bytes.fromhex("ac")]
    digests = [hash256(tx(code, output_script, **tx_params) + struct.pack("<I", 1))
               for code in codes]
    z1, z2 = [int.from_bytes(digest, "big") % N for digest in digests]
    r = G[0] % N
    s = ((z1 - z2) * pow(2, -1, N)) % N
    d = (-(z1 + z2) * pow(2 * r, -1, N)) % N
    assert z1 != z2 and s and d
    s = min(s, N - s)
    q = mul(d)
    results = [verify(z, r, s, q) for z in (z1, z2)]
    assert all(result[0] for result in results)
    assert results[0][1][0] == results[1][1][0]
    assert (results[0][1][1] + results[1][1][1]) % P == 0
    der_body = signature_integer(r) + signature_integer(s)
    der = b"\x30" + vector(der_body)
    sig = der + b"\x01"
    pubkey = bytes([2 + q[1] % 2]) + q[0].to_bytes(32, "big")
    with tempfile.TemporaryDirectory(prefix="legacy-ecdsa-vector-") as tmp:
        folder = Path(tmp)
        # DER SubjectPublicKeyInfo: id-ecPublicKey + secp256k1 + compressed key.
        spki = bytes.fromhex("3036301006072a8648ce3d020106052b8104000a032200") + pubkey
        (folder / "key.der").write_bytes(spki)
        (folder / "sig.der").write_bytes(der)
        independent = []
        for index, digest in enumerate(digests):
            (folder / "digest.bin").write_bytes(digest)
            run = subprocess.run([
                "/usr/bin/openssl", "pkeyutl", "-verify", "-pubin", "-keyform", "DER",
                "-inkey", str(folder / "key.der"), "-sigfile", str(folder / "sig.der"),
                "-in", str(folder / "digest.bin"), "-pkeyopt", "digest:sha256",
            ], capture_output=True, text=True, check=True)
            independent.append(run.stdout.strip())
    script_sig = vector(sig) + vector(pubkey)
    if p2sh:
        script_sig += vector(SCRIPT)
    return {
        "name": name, "script_pubkey": SCRIPT.hex(),
        "script_codes": [code.hex() for code in codes],
        "output_script": output_script.hex(),
        "digest_hex": [digest.hex() for digest in digests],
        "same_signature": sig.hex(), "same_public_key": pubkey.hex(),
        "known_private_scalar": f"{d:064x}",
        "locally_verified": [result[0] for result in results],
        "openssl_verification": independent,
        "spending_transaction_hex": tx(script_sig, output_script, **tx_params).hex(),
        "locking_script_bytes": len(SCRIPT), "static_non_push_opcodes": 4,
        "script_sig_bytes": len(script_sig), "witness_bytes": 0,
        "complete_input_stack_items": 2, "hint_stack_items": 0,
        "combined_stack_peak_by_inspection": 4,
    }


if __name__ == "__main__":
    report = {
        "question": "Do identical free ECDSA signatures and public keys force identical digests across CODESEPARATOR contexts?",
        "answer": False,
        "evidence": "differentially-validated",
        "deployment_class": "unclassified",
        "scope": "ECDSA equations compared with OpenSSL; synthetic unspent outpoint, no complete Bitcoin consensus execution.",
        "openssl_version": subprocess.check_output(["/usr/bin/openssl", "version"], text=True).strip(),
        "vectors": [make_vector("allowed-output", bytes.fromhex("0014") + b"\x11" * 20),
                    make_vector("different-output", bytes.fromhex("0014") + b"\x22" * 20)],
    }
    print(json.dumps(report, indent=2))
