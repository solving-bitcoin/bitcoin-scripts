//! Serialization-only sizing of a 187-fixed-point funding/spending pair.
//! This has no selectable digit slots and is NOT a 256-byte BitVM3 proof.
//! Uses real point-lock signatures, selecting deterministic scalar counters
//! with 60-byte signatures. P2TR witnesses contain 64-byte size placeholders;
//! this is not a consensus/policy validation or a broadcastable transaction.
use bitcoin::{
    absolute,
    consensus::serialize,
    hashes::Hash,
    script::{Builder, PushBytesBuf},
    secp256k1::{PublicKey, Secp256k1, SecretKey},
    transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use bitcoin_lab::{
    signatures::pointlocks::committed_two_check as lock,
    support::script::{script, ScriptCompilation},
};

fn input(previous_output: OutPoint, script_sig: ScriptBuf, witness: Witness) -> TxIn {
    TxIn {
        previous_output,
        script_sig,
        sequence: Sequence::MAX,
        witness,
    }
}

fn report(name: &str, tx: &Transaction) {
    let mut stripped = tx.clone();
    for input in &mut stripped.input {
        input.witness = Witness::new();
    }
    let base = serialize(&stripped).len();
    let total = serialize(tx).len();
    println!("{name}: inputs={} outputs={} base_bytes={base} witness_and_marker_bytes={} total_bytes={total} weight={} vsize={}",
        tx.input.len(), tx.output.len(), total-base, tx.weight().to_wu(), tx.vsize());
}

fn main() {
    let secp = Secp256k1::new();
    let mut locks = Vec::new();
    let mut signatures = Vec::new();
    let mut counter = 1u32;
    while locks.len() < 187 {
        let mut bytes = [0; 32];
        bytes[28..].copy_from_slice(&counter.to_be_bytes());
        counter += 1;
        let secret = SecretKey::from_slice(&bytes).unwrap();
        let signature = lock::sign(secret).unwrap();
        if signature.to_vec().len() != 60 {
            continue;
        }
        let target = PublicKey::from_secret_key(&secp, &secret);
        locks.push(lock::point_lock(target, lock::signature_commitment(&signature)).unwrap());
        signatures.push(signature.to_vec());
    }
    let internal_key = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[7; 32]).unwrap())
        .x_only_public_key()
        .0;
    let p2tr = ScriptBuf::new_p2tr(&secp, internal_key, None);
    let key_witness = Witness::from_slice(&[vec![0; 64]]);
    let mut funding = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![input(
            OutPoint {
                txid: bitcoin::Txid::all_zeros(),
                vout: 0,
            },
            ScriptBuf::new(),
            key_witness.clone(),
        )],
        output: vec![TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: p2tr.clone(),
        }],
    };
    let mut redeems = Vec::new();
    for batch in locks.chunks(5) {
        let redeem = script! {
            for i in 0..batch.len() {
                { batch[i].clone() }
                if i + 1 < batch.len() { OP_VERIFY }
            }
        }
        .compile_with_policy();
        assert_eq!(redeem.len(), batch.len() * 100);
        funding.output.push(TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: redeem.to_p2sh(),
        });
        redeems.push(redeem);
    }
    let txid = funding.compute_txid();
    let mut assertion = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![input(
            OutPoint { txid, vout: 0 },
            ScriptBuf::new(),
            key_witness,
        )],
        output: vec![TxOut {
            value: Amount::from_sat(3_800_000),
            script_pubkey: p2tr,
        }],
    };
    for (index, (redeem, batch)) in redeems.iter().zip(signatures.chunks(5)).enumerate() {
        let mut builder = Builder::new();
        for signature in batch.iter().rev() {
            builder = builder.push_slice(PushBytesBuf::try_from(signature.clone()).unwrap());
        }
        let script_sig = builder
            .push_slice(PushBytesBuf::try_from(redeem.to_bytes()).unwrap())
            .into_script();
        assert_eq!(script_sig.len(), if batch.len() == 5 { 808 } else { 324 });
        assertion.input.push(input(
            OutPoint {
                txid,
                vout: index as u32 + 1,
            },
            script_sig,
            Witness::new(),
        ));
    }
    assert_eq!(funding.output.len(), 39);
    assert_eq!(assertion.input.len(), 39);
    assert_eq!(funding.vsize(), 1327);
    assert_eq!(assertion.vsize(), 31975);
    report("funding", &funding);
    report("fixed_point_spend", &assertion);
    println!("combined_vsize={}", funding.vsize() + assertion.vsize());
}
