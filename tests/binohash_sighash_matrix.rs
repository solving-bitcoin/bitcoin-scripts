//! Host-side commitment matrix for legacy sighash modes used in Binohash pinning.
//! No local Script execution or Bitcoin Core consensus verdict is claimed.

use bitcoin::{
    absolute, hashes::Hash, transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
    TxOut, Txid, Witness,
};
use bitcoin_lab::introspection::binohash::{binohash_digest, push_data};

const MODES: [(u32, &str); 6] = [
    (0x01, "ALL"),
    (0x02, "NONE"),
    (0x03, "SINGLE"),
    (0x81, "ALL|ANYONECANPAY"),
    (0x82, "NONE|ANYONECANPAY"),
    (0x83, "SINGLE|ANYONECANPAY"),
];

fn fixture() -> (Transaction, ScriptBuf, Vec<Vec<u8>>) {
    let input = |byte: u8| TxIn {
        previous_output: OutPoint {
            txid: Txid::from_byte_array([byte; 32]),
            vout: byte as u32,
        },
        script_sig: ScriptBuf::new(),
        sequence: Sequence(0xffff_ff00 + byte as u32),
        witness: Witness::new(),
    };
    let output = |value| TxOut {
        value: Amount::from_sat(value),
        script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
    };
    let signatures = vec![b"pool-a".to_vec(), b"pool-b".to_vec()];
    let script_code = ScriptBuf::from_bytes(
        signatures
            .iter()
            .flat_map(|signature| push_data(signature))
            .chain([0x51])
            .collect(),
    );
    (
        Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![input(1), input(2)],
            output: vec![output(1_000), output(2_000)],
        },
        script_code,
        signatures,
    )
}

fn digest(tx: &Transaction, script: &ScriptBuf, signatures: &[Vec<u8>], mode: u32) -> [u8; 32] {
    binohash_digest(tx, 1, script, signatures, &[0], mode).unwrap()
}

#[test]
fn legacy_mode_commitment_matrix_for_selected_input_one() {
    let (base, script, signatures) = fixture();
    let cases: [(&str, fn(&mut Transaction), [bool; 6]); 8] = [
        (
            "version",
            |tx| tx.version = transaction::Version::ONE,
            [true; 6],
        ),
        (
            "locktime",
            |tx| tx.lock_time = absolute::LockTime::from_consensus(500),
            [true; 6],
        ),
        (
            "selected prevout",
            |tx| tx.input[1].previous_output.vout += 1,
            [true; 6],
        ),
        (
            "selected sequence",
            |tx| tx.input[1].sequence = Sequence(42),
            [true; 6],
        ),
        (
            "other prevout",
            |tx| tx.input[0].previous_output.vout += 1,
            [true, true, true, false, false, false],
        ),
        (
            "other sequence",
            |tx| tx.input[0].sequence = Sequence(42),
            [true, false, false, false, false, false],
        ),
        (
            "selected output",
            |tx| tx.output[1].value = Amount::from_sat(2_001),
            [true, false, true, true, false, true],
        ),
        (
            "other output",
            |tx| tx.output[0].value = Amount::from_sat(1_001),
            [true, false, false, true, false, false],
        ),
    ];
    for (mode_index, (mode, name)) in MODES.iter().enumerate() {
        let baseline = digest(&base, &script, &signatures, *mode);
        for (label, mutate, expected_change) in cases {
            let mut changed = base.clone();
            mutate(&mut changed);
            assert_eq!(
                digest(&changed, &script, &signatures, *mode) != baseline,
                expected_change[mode_index],
                "{name}: {label}"
            );
        }
    }
}

#[test]
fn single_bug_is_a_separate_non_committing_boundary() {
    let (mut base, script, signatures) = fixture();
    base.output.pop(); // selected input index 1 now exceeds output count 1
    let mut changed = base.clone();
    changed.version = transaction::Version::ONE;
    changed.input[1].previous_output.vout += 1;
    changed.output[0].value = Amount::from_sat(9_999);
    for mode in [0x03, 0x83] {
        let z = digest(&base, &script, &signatures, mode);
        assert_eq!(z[0], 1);
        assert!(z[1..].iter().all(|byte| *byte == 0));
        assert_eq!(digest(&changed, &script, &signatures, mode), z);
    }
}
