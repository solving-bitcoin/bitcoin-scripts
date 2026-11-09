//! Pinned-chain comparisons for the shared Core harness.
use super::{expectations, fixture, script, sha256, Hash, ScriptCompilation, Value, POLICY};
use bitcoin_lab::commitments::hash_path::{
    hash_path_commitment, hash_path_integer_commitment, hash_path_integer_witness, pinned::verify,
    verify_hash_path_chain,
};

pub(super) fn fixtures() -> Vec<Value> {
    let x = [0x42; 32];
    let start = sha256::Hash::hash(&x).to_byte_array();
    let a = hash_path_integer_commitment(&x, 13, 4);
    let b = hash_path_integer_commitment(&a, 3, 3);
    let unbound = verify_hash_path_chain(4, a, 3, b);
    let length = script! {OP_SIZE 32 OP_EQUALVERIFY {unbound.clone()}};
    let pinned = verify(start, &[(4, a), (3, b)]);
    let mut second = hash_path_integer_witness(&a, 3, 3);
    second.pop();
    let mut honest = second.clone();
    honest.extend(hash_path_integer_witness(&x, 13, 4));
    let mut forged = second;
    forged.extend(hash_path_integer_witness(&start, 12, 4));
    let mut stale = a;
    stale[0] ^= 1;
    let mut reordered = hash_path_integer_witness(&[], 13, 4);
    reordered.pop();
    reordered.extend(hash_path_integer_witness(&x, 3, 3));
    let mut bad_bit = honest.clone();
    bad_bit[6] = vec![2];
    let mut cases = vec![
        (
            "valid-4-plus-3",
            "Both ordered checkpoints and starting hash match.",
            pinned.clone(),
            honest.clone(),
            None,
        ),
        (
            "control-unbound-valid",
            "Unbound control with identical honest data.",
            unbound.clone(),
            honest.clone(),
            None,
        ),
        (
            "control-length-only-valid",
            "32-byte length control with identical honest data.",
            length.clone(),
            honest.clone(),
            None,
        ),
        (
            "control-unbound-substitution",
            "SHA256(x) with first bit zero preserves the checkpoints.",
            unbound,
            forged.clone(),
            None,
        ),
        (
            "control-length-only-substitution",
            "The length check accepts the same substitution.",
            length,
            forged.clone(),
            None,
        ),
        (
            "rejects-first-bit-substitution",
            "The independent SHA-256 pin rejects the substituted preimage.",
            pinned.clone(),
            forged,
            Some("equalverify"),
        ),
        (
            "stale-first-checkpoint",
            "The first checkpoint is wrong; the final checkpoint is unchanged.",
            verify(start, &[(4, stale), (3, b)]),
            honest,
            Some("equalverify"),
        ),
        (
            "reordered-rounds",
            "Changing round order breaks the first checkpoint.",
            pinned.clone(),
            reordered,
            Some("equalverify"),
        ),
        (
            "nonminimal-selector",
            "A truthy value other than 01 violates tapscript MINIMALIF.",
            pinned,
            bad_bit,
            Some("tapscript-minimal-if"),
        ),
    ];
    for bit in [false, true] {
        let digest = hash_path_commitment(&x, &vec![bit; 997]);
        let leaf = verify(start, &[(997, digest)]);
        let mut data = vec![if bit { vec![1] } else { vec![] }; 997];
        data.push(x.to_vec());
        cases.push((
            if bit { "997-ones" } else { "997-zeroes" },
            "998 entry data items and two transient items during the start pin.",
            leaf.clone(),
            data.clone(),
            None,
        ));
        if !bit {
            data.insert(0, vec![77]);
            cases.push((
                "997-one-extra-live-item",
                "The extra item causes a transient combined-stack overflow.",
                leaf,
                data,
                Some("stack-size"),
            ));
        }
    }
    cases
        .into_iter()
        .map(|(name, desc, leaf, data, error)| {
            fixture(
                &format!("pinned-chain-{name}"),
                desc,
                leaf.compile_with_policy(),
                data,
                POLICY,
                expectations(error, None),
            )
        })
        .collect()
}
