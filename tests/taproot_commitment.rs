use bitcoin::{
    secp256k1::{Keypair, Secp256k1, SecretKey},
    taproot::{LeafVersion, TaprootBuilder},
    transaction, Amount, ScriptBuf, Transaction, TxIn, TxOut, Witness,
};
use bitcoin_lab::support::taproot::{
    verify_taproot_input_commitment, verify_taproot_script_path_commitment,
    TaprootCommitmentError as Error,
};

fn key(seed: u8) -> Keypair {
    Keypair::from_secret_key(
        &Secp256k1::new(),
        &SecretKey::from_slice(&[seed; 32]).unwrap(),
    )
}

fn case(depth: u8, leaf_version: LeafVersion) -> (ScriptBuf, Witness) {
    let secp = Secp256k1::new();
    let script = ScriptBuf::from_bytes(vec![0x51]); // OP_TRUE
    let mut builder = TaprootBuilder::new()
        .add_leaf_with_ver(depth, script.clone(), leaf_version)
        .unwrap();
    if depth == 1 {
        builder = builder
            .add_leaf(1, ScriptBuf::from_bytes(vec![0x00]))
            .unwrap();
    }
    let spend = builder
        .finalize(&secp, key(1).x_only_public_key().0)
        .unwrap();
    let control = spend
        .control_block(&(script.clone(), leaf_version))
        .unwrap()
        .serialize();
    (
        ScriptBuf::new_p2tr_tweaked(spend.output_key()),
        Witness::from_slice(&[vec![1], script.to_bytes(), control]),
    )
}

#[test]
fn verifies_both_merkle_depths_and_annex() {
    for depth in [0, 1] {
        let (output, mut witness) = case(depth, LeafVersion::TapScript);
        assert_eq!(
            verify_taproot_script_path_commitment(&output, &witness),
            Ok(LeafVersion::TapScript)
        );
        witness.push(vec![0x50, 0xaa, 0xbb]);
        assert_eq!(
            verify_taproot_script_path_commitment(&output, &witness),
            Ok(LeafVersion::TapScript)
        );
        // An item before the script is data, even if it starts with 0x50.
        let mut items = witness.to_vec();
        items.pop();
        items.insert(1, vec![0x50]);
        assert_eq!(
            verify_taproot_script_path_commitment(&output, &Witness::from_slice(&items)),
            Ok(LeafVersion::TapScript)
        );
    }
}

#[test]
fn mutated_commitments_gate_leaf_acceptance() {
    for depth in [0, 1] {
        let (output, witness) = case(depth, LeafVersion::TapScript);
        let original = witness.to_vec();

        let mut parity = original.clone();
        parity[2][0] ^= 1;
        assert_eq!(
            verify_taproot_script_path_commitment(&output, &Witness::from_slice(&parity)),
            Err(Error::CommitmentMismatch)
        );

        let mut script = original.clone();
        script[1][0] = 0x00;
        assert_eq!(
            verify_taproot_script_path_commitment(&output, &Witness::from_slice(&script)),
            Err(Error::CommitmentMismatch)
        );

        let mut internal_key = original.clone();
        internal_key[2][1..33].copy_from_slice(&key(2).x_only_public_key().0.serialize());
        assert_eq!(
            verify_taproot_script_path_commitment(&output, &Witness::from_slice(&internal_key)),
            Err(Error::CommitmentMismatch)
        );

        if depth == 1 {
            let mut sibling = original.clone();
            sibling[2][33] ^= 1;
            assert_eq!(
                verify_taproot_script_path_commitment(&output, &Witness::from_slice(&sibling)),
                Err(Error::CommitmentMismatch)
            );
        }
    }
}

#[test]
fn separates_unsupported_and_malformed_contexts() {
    let (output, witness) = case(0, LeafVersion::TapScript);
    let (other_output, _) = case(1, LeafVersion::TapScript);
    assert_eq!(
        verify_taproot_script_path_commitment(&other_output, &witness),
        Err(Error::CommitmentMismatch)
    );
    assert_eq!(
        verify_taproot_script_path_commitment(&ScriptBuf::new(), &witness),
        Err(Error::NotP2trOutput)
    );
    let mut invalid_key = vec![0x51, 0x20];
    invalid_key.extend([0xff; 32]);
    assert_eq!(
        verify_taproot_script_path_commitment(&ScriptBuf::from_bytes(invalid_key), &witness),
        Err(Error::InvalidOutputKey)
    );
    assert_eq!(
        verify_taproot_script_path_commitment(&output, &Witness::new()),
        Err(Error::EmptyWitness)
    );
    assert_eq!(
        verify_taproot_script_path_commitment(&output, &Witness::from_slice(&[vec![1]])),
        Err(Error::KeyPathWitness)
    );
    assert_eq!(
        verify_taproot_script_path_commitment(
            &output,
            &Witness::from_slice(&[vec![1], vec![0x50]])
        ),
        Err(Error::KeyPathWitness)
    );
    for size in [32, 34, 33 + 32 * 129] {
        let malformed = Witness::from_slice(&[vec![1], vec![0x51], vec![0xc0; size]]);
        assert_eq!(
            verify_taproot_script_path_commitment(&output, &malformed),
            Err(Error::InvalidControlBlock),
            "control size {size}"
        );
    }
    let mut misplaced = witness.to_vec();
    misplaced.push(vec![0x01]);
    assert_eq!(
        verify_taproot_script_path_commitment(&output, &Witness::from_slice(&misplaced)),
        Err(Error::InvalidControlBlock)
    );
}

#[test]
fn future_leaf_commitment_is_valid_without_execution_claim() {
    let future = LeafVersion::from_consensus(0xc2).unwrap();
    let (output, witness) = case(0, future);
    assert_eq!(
        verify_taproot_script_path_commitment(&output, &witness),
        Ok(future)
    );
}

#[test]
fn selects_the_transaction_input_and_matching_prevout() {
    let (output, witness) = case(0, LeafVersion::TapScript);
    let tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            witness,
            ..Default::default()
        }],
        output: vec![],
    };
    let prevout = TxOut {
        value: Amount::from_sat(1_000),
        script_pubkey: output,
    };
    assert_eq!(
        verify_taproot_input_commitment(&tx, 0, &[prevout.clone()]),
        Ok(LeafVersion::TapScript)
    );
    assert_eq!(
        verify_taproot_input_commitment(&tx, 1, &[prevout.clone()]),
        Err(Error::InputIndexOutOfBounds)
    );
    assert_eq!(
        verify_taproot_input_commitment(&tx, 0, &[]),
        Err(Error::PrevoutCountMismatch)
    );
}
