//! Integration boundary for the fallible complete-witness research helper.
//! These local checks do not establish commitment or transaction validity.

use bitcoin::{
    absolute,
    secp256k1::{Keypair, Secp256k1, SecretKey},
    taproot::{LeafVersion, TaprootBuilder},
    transaction, Amount, ScriptBuf, Transaction, TxIn, TxOut, Witness,
};
use bitcoin_lab::support::{
    execution::{dry_run_taproot_input, try_dry_run_taproot_input},
    script::{script, ScriptCompilation},
};

fn input(annex_len: usize) -> (Transaction, TxOut) {
    let script = script! { OP_DROP OP_TRUE }.compile_with_policy();
    let secp = Secp256k1::new();
    let key = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[1; 32]).unwrap());
    let spend = TaprootBuilder::new()
        .add_leaf(0, script.clone())
        .unwrap()
        .finalize(&secp, key.x_only_public_key().0)
        .unwrap();
    let control = spend
        .control_block(&(script.clone(), LeafVersion::TapScript))
        .unwrap()
        .serialize();
    let mut witness = vec![vec![1], script.to_bytes(), control];
    if annex_len > 0 {
        let mut annex = vec![0x55; annex_len];
        annex[0] = 0x50;
        witness.push(annex);
    }
    (
        Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                witness: Witness::from_slice(&witness),
                ..Default::default()
            }],
            output: vec![],
        },
        TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::new_p2tr_tweaked(spend.output_key()),
        },
    )
}

#[test]
fn dry_run_budget_counts_the_complete_witness_and_annex() {
    for annex_len in [0, 1, 252, 253] {
        let (tx, prevout) = input(annex_len);
        let expected = 50 + tx.input[0].witness.size() as i64;
        let result = try_dry_run_taproot_input(&tx, 0, &[prevout.clone()]).unwrap();
        assert!(result.success, "annex_len={annex_len}: {result}");
        assert!(result.stack_limit_enforced);
        assert_eq!(result.stats.start_validation_weight, expected);
        assert_eq!(result.stats.validation_weight, expected);
        assert_eq!(result.final_stack.len(), 1);
        assert_eq!(result.final_stack.get(0), vec![1]);
        let convenience = dry_run_taproot_input(&tx, 0, &[prevout]);
        assert_eq!(convenience.stats.start_validation_weight, expected);
        assert!(convenience.success);
    }
}

#[test]
fn malformed_input_context_is_an_initialization_error() {
    let (mut tx, prevout) = input(0);
    assert!(try_dry_run_taproot_input(&tx, 1, &[prevout.clone()]).is_err());
    assert!(try_dry_run_taproot_input(&tx, 0, &[]).is_err());
    assert!(try_dry_run_taproot_input(&tx, 0, &[prevout.clone(), prevout.clone()]).is_err());
    for witness in [vec![], vec![vec![0; 64]], vec![vec![0x51], vec![0xc0]]] {
        tx.input[0].witness = Witness::from_slice(&witness);
        assert!(try_dry_run_taproot_input(&tx, 0, &[prevout.clone()]).is_err());
    }
}
