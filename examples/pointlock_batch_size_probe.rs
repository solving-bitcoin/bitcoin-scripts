//! Size-only experiment for HASH160-committed two-check point-lock batches.
//! Run: cargo run --locked --example pointlock_batch_size_probe
//! Measures policy-compiled complete AND predicates for 1..=6 locks, with
//! deterministic public scalar seeds [7;32] through [12;32]. Each lock takes
//! one signature data item and zero hints; all signatures coexist at entry.
//! Excludes scriptSig/witness serialization, P2SH funding wrapper, transaction
//! framing, payment authorization and refunds. No Script/Core execution is
//! performed: evidence is locally-reproduced sizing, deployment unclassified.
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin_lab::{
    signatures::pointlocks,
    support::script::{script, ScriptCompilation},
};

fn main() {
    let secp = Secp256k1::new();
    for count in 1..=6usize {
        let locks: Vec<_> = (0..count)
            .map(|i| {
                let secret = SecretKey::from_slice(&[7 + i as u8; 32]).unwrap();
                let target = PublicKey::from_secret_key(&secp, &secret);
                let signature = pointlocks::two_check::sign(secret).unwrap();
                pointlocks::committed_two_check::point_lock(
                    target,
                    pointlocks::committed_two_check::signature_commitment(&signature),
                )
                .unwrap()
            })
            .collect();
        let hash160_compiled = script! {
            for i in 0..count {
                { locks[i].clone() }
                if i + 1 < count { OP_VERIFY }
            }
        }
        .compile_with_policy();
        println!(
            "hash=HASH160 locks={count} policy_compiled_script_bytes={}",
            hash160_compiled.len()
        );
    }
}
