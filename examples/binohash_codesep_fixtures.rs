//! Legacy OP_CODESEPARATOR and FindAndDelete fixture for pinned Bitcoin Core.
//!
//! Raw consensus bytecode is intentional: exact signature-push positions and
//! separator boundaries are the behavior under test. Public deterministic keys
//! provide no Binohash grinding or collision-security evidence.

use bitcoin::{
    absolute,
    consensus::serialize,
    hashes::{hash160, Hash},
    hex::{DisplayHex, FromHex},
    opcodes::all::OP_CODESEPARATOR,
    script::Instruction,
    secp256k1::{Message, PublicKey, Secp256k1, SecretKey},
    transaction, Amount, OutPoint, Script, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness,
};
use bitcoin_lab::introspection::binohash::{binohash_digest, push_data};
use serde_json::{json, Value};
use std::str::FromStr;

const INPUT_VALUE: u64 = 1_000_000;
const FEE: u64 = 20_000;
const SIGHASH_ALL: u8 = 0x01;
const SIGHASH_SINGLE: u8 = 0x03;
const SIGHASH_SINGLE_ANYONECANPAY: u8 = 0x83;

struct BoundaryScript {
    redeem: ScriptBuf,
    operative_suffix: ScriptBuf,
    dead_suffix: ScriptBuf,
    operative_offset: usize,
    dead_offset: usize,
}

fn p2sh(script: &[u8]) -> ScriptBuf {
    let digest = hash160::Hash::hash(script);
    ScriptBuf::from_bytes(
        [
            vec![0xa9, 0x14],
            digest.to_byte_array().to_vec(),
            vec![0x87],
        ]
        .concat(),
    )
}

fn input(txid: Txid, vout: u32) -> TxIn {
    TxIn {
        previous_output: OutPoint { txid, vout },
        script_sig: ScriptBuf::new(),
        sequence: Sequence::MAX,
        witness: Witness::new(),
    }
}

fn script_sig(puzzle_signature: &[u8], choose_before: bool, redeem: &[u8]) -> ScriptBuf {
    ScriptBuf::from_bytes(
        [
            vec![0x00], // CHECKMULTISIG dummy
            push_data(puzzle_signature),
            vec![if choose_before { 0x51 } else { 0x00 }],
            push_data(redeem),
        ]
        .concat(),
    )
}

fn transaction_record(tx: &Transaction) -> Value {
    json!({
        "hex": serialize(tx).to_lower_hex_string(),
        "txid": tx.compute_txid().to_string(),
        "weight": tx.weight().to_wu(),
        "vsize": tx.vsize(),
        "base_bytes": tx.base_size(),
        "total_bytes": tx.total_size(),
        "input_script_sig_bytes": tx.input.iter().map(|input| input.script_sig.len()).collect::<Vec<_>>(),
    })
}

fn strip_code_separators(script: &Script) -> ScriptBuf {
    let mut output = Vec::with_capacity(script.len());
    let mut copied_until = 0;
    for instruction in script.instruction_indices() {
        let (index, instruction) = instruction.expect("fixture script must parse");
        if instruction == Instruction::Op(OP_CODESEPARATOR) {
            output.extend_from_slice(&script.as_bytes()[copied_until..index]);
            copied_until = index + 1;
        }
    }
    output.extend_from_slice(&script.as_bytes()[copied_until..]);
    ScriptBuf::from_bytes(output)
}

fn boundary_script(
    pool_before: &[u8],
    pool_after: &[u8],
    puzzle_pubkey: &[u8],
    pool_pubkey: &[u8],
) -> BoundaryScript {
    let mut script = vec![0x76, 0x6b, 0x63]; // DUP TOALTSTACK IF
    script.extend(push_data(pool_before));
    script.push(0x68); // ENDIF
    script.push(0xab); // the always-executed OP_CODESEPARATOR
    let operative_offset = script.len();

    script.extend([0x6c, 0x64]); // FROMALTSTACK NOTIF
    script.extend(push_data(pool_after));
    script.push(0x68); // ENDIF
    script.extend([0x00, 0x63, 0xab]); // OP_0 OP_IF dead OP_CODESEPARATOR
    let dead_offset = script.len();
    script.push(0x68); // ENDIF
    script.push(0x52); // two signatures
    script.extend(push_data(puzzle_pubkey));
    script.extend(push_data(pool_pubkey));
    script.extend([0x52, 0xae]); // two pubkeys, CHECKMULTISIG

    let redeem = ScriptBuf::from_bytes(script);
    BoundaryScript {
        operative_suffix: ScriptBuf::from_bytes(redeem.as_bytes()[operative_offset..].to_vec()),
        dead_suffix: ScriptBuf::from_bytes(redeem.as_bytes()[dead_offset..].to_vec()),
        operative_offset,
        dead_offset,
        redeem,
    }
}

fn signed_transaction(
    base: &Transaction,
    digest: [u8; 32],
    key: &SecretKey,
    choose_before: bool,
    redeem: &[u8],
) -> (Value, Vec<u8>) {
    let secp = Secp256k1::new();
    let mut signature = secp
        .sign_ecdsa(&Message::from_digest(digest), key)
        .serialize_der()
        .to_vec();
    signature.push(SIGHASH_ALL);
    let mut tx = base.clone();
    tx.input[1].script_sig = script_sig(&signature, choose_before, redeem);
    (transaction_record(&tx), signature)
}

fn generate(funding_txid: Txid, destination: ScriptBuf) -> Value {
    let secp = Secp256k1::new();
    let pool_key = SecretKey::from_slice(&[1; 32]).unwrap();
    let puzzle_key = SecretKey::from_slice(&[2; 32]).unwrap();
    let pool_pubkey = PublicKey::from_secret_key(&secp, &pool_key).serialize();
    let puzzle_pubkey = PublicKey::from_secret_key(&secp, &puzzle_key).serialize();

    let mut bug_digest = [0_u8; 32];
    bug_digest[0] = 1;
    let pool_der = secp
        .sign_ecdsa(&Message::from_digest(bug_digest), &pool_key)
        .serialize_der();
    let mut pool_before = pool_der.to_vec();
    pool_before.push(SIGHASH_SINGLE);
    let mut pool_after = pool_der.to_vec();
    pool_after.push(SIGHASH_SINGLE_ANYONECANPAY);
    let pool = [pool_before.clone(), pool_after.clone()];

    let boundaries = boundary_script(&pool_before, &pool_after, &puzzle_pubkey, &pool_pubkey);
    assert!(boundaries.redeem.len() <= 520);
    let easy_redeem = ScriptBuf::from_bytes(vec![0x51]);
    let choices = [
        ("before-operative-boundary", true, 0_u32, 1_u32, 0_usize),
        ("after-operative-boundary", false, 2_u32, 3_u32, 1_usize),
    ];
    let rows = choices
        .iter()
        .map(
            |(name, choose_before, easy_vout, bino_vout, selected_index)| {
                let mut base = Transaction {
                    version: transaction::Version::TWO,
                    lock_time: absolute::LockTime::ZERO,
                    input: vec![
                        input(funding_txid, *easy_vout),
                        input(funding_txid, *bino_vout),
                    ],
                    output: vec![TxOut {
                        value: Amount::from_sat(2 * INPUT_VALUE - FEE),
                        script_pubkey: destination.clone(),
                    }],
                };
                base.input[0].script_sig =
                    ScriptBuf::from_bytes(push_data(easy_redeem.as_bytes()));

                // rust-bitcoin deliberately leaves CODESEPARATOR evaluation to
                // the caller. Core first chooses the suffix after the last
                // executed separator, then omits every parsed separator opcode
                // while serializing that suffix for legacy sighash.
                let operative_signing_script =
                    strip_code_separators(&boundaries.operative_suffix);
                let full_signing_script = strip_code_separators(&boundaries.redeem);
                let dead_signing_script = strip_code_separators(&boundaries.dead_suffix);
                let correct_digest = binohash_digest(
                    &base,
                    1,
                    &operative_signing_script,
                    &pool,
                    &[*selected_index],
                    u32::from(SIGHASH_ALL),
                )
                .unwrap();
                let full_boundary_digest = binohash_digest(
                    &base,
                    1,
                    &full_signing_script,
                    &pool,
                    &[*selected_index],
                    u32::from(SIGHASH_ALL),
                )
                .unwrap();
                let dead_boundary_digest = binohash_digest(
                    &base,
                    1,
                    &dead_signing_script,
                    &pool,
                    &[*selected_index],
                    u32::from(SIGHASH_ALL),
                )
                .unwrap();
                let retained_dead_separator_digest = binohash_digest(
                    &base,
                    1,
                    &boundaries.operative_suffix,
                    &pool,
                    &[*selected_index],
                    u32::from(SIGHASH_ALL),
                )
                .unwrap();
                let wrong_find_and_delete_indices: Vec<usize> = if *choose_before {
                    vec![1]
                } else {
                    vec![]
                };
                let wrong_find_and_delete_digest = binohash_digest(
                    &base,
                    1,
                    &operative_signing_script,
                    &pool,
                    &wrong_find_and_delete_indices,
                    u32::from(SIGHASH_ALL),
                )
                .unwrap();
                assert_ne!(correct_digest, full_boundary_digest);
                assert_ne!(correct_digest, dead_boundary_digest);
                assert_ne!(correct_digest, retained_dead_separator_digest);
                assert_ne!(correct_digest, wrong_find_and_delete_digest);
                let digest_views = [
                    correct_digest,
                    full_boundary_digest,
                    dead_boundary_digest,
                    retained_dead_separator_digest,
                    wrong_find_and_delete_digest,
                ];
                for (index, digest) in digest_views.iter().enumerate() {
                    assert!(!digest_views[..index].contains(digest));
                }

                let (valid, valid_signature) = signed_transaction(
                    &base,
                    correct_digest,
                    &puzzle_key,
                    *choose_before,
                    boundaries.redeem.as_bytes(),
                );
                let (wrong_full_boundary, _) = signed_transaction(
                    &base,
                    full_boundary_digest,
                    &puzzle_key,
                    *choose_before,
                    boundaries.redeem.as_bytes(),
                );
                let (wrong_dead_boundary, _) = signed_transaction(
                    &base,
                    dead_boundary_digest,
                    &puzzle_key,
                    *choose_before,
                    boundaries.redeem.as_bytes(),
                );
                let (wrong_find_and_delete, _) = signed_transaction(
                    &base,
                    wrong_find_and_delete_digest,
                    &puzzle_key,
                    *choose_before,
                    boundaries.redeem.as_bytes(),
                );
                let (wrong_retained_dead_separator, _) = signed_transaction(
                    &base,
                    retained_dead_separator_digest,
                    &puzzle_key,
                    *choose_before,
                    boundaries.redeem.as_bytes(),
                );
                json!({
                    "name": name,
                    "selected_index": selected_index,
                    "selected_push_position": if *choose_before { "before" } else { "after" },
                    "correct_digest_hex": correct_digest.to_lower_hex_string(),
                    "full_boundary_digest_hex": full_boundary_digest.to_lower_hex_string(),
                    "dead_boundary_digest_hex": dead_boundary_digest.to_lower_hex_string(),
                    "retained_dead_separator_digest_hex": retained_dead_separator_digest.to_lower_hex_string(),
                    "wrong_find_and_delete_digest_hex": wrong_find_and_delete_digest.to_lower_hex_string(),
                    "valid_puzzle_signature_hex": valid_signature.to_lower_hex_string(),
                    "valid": valid,
                    "wrong_full_boundary": wrong_full_boundary,
                    "wrong_dead_boundary": wrong_dead_boundary,
                    "wrong_retained_dead_separator": wrong_retained_dead_separator,
                    "wrong_find_and_delete": wrong_find_and_delete,
                })
            },
        )
        .collect::<Vec<_>>();

    assert_ne!(rows[0]["correct_digest_hex"], rows[1]["correct_digest_hex"]);
    json!({
        "experiment": "binohash-legacy-codesep-findanddelete-core",
        "funding_txid": funding_txid.to_string(),
        "input_value_sat": INPUT_VALUE,
        "fee_sat": FEE,
        "redeem_script_hex": boundaries.redeem.as_bytes().to_lower_hex_string(),
        "redeem_script_bytes": boundaries.redeem.len(),
        "operative_codesep_offset": boundaries.operative_offset - 1,
        "operative_suffix_offset": boundaries.operative_offset,
        "dead_codesep_offset": boundaries.dead_offset - 1,
        "dead_suffix_offset": boundaries.dead_offset,
        "operative_suffix_hex": boundaries.operative_suffix.as_bytes().to_lower_hex_string(),
        "dead_suffix_hex": boundaries.dead_suffix.as_bytes().to_lower_hex_string(),
        "operative_signing_script_hex": strip_code_separators(&boundaries.operative_suffix).as_bytes().to_lower_hex_string(),
        "full_signing_script_hex": strip_code_separators(&boundaries.redeem).as_bytes().to_lower_hex_string(),
        "dead_signing_script_hex": strip_code_separators(&boundaries.dead_suffix).as_bytes().to_lower_hex_string(),
        "binohash_script_pubkey_hex": p2sh(boundaries.redeem.as_bytes()).as_bytes().to_lower_hex_string(),
        "easy_script_pubkey_hex": p2sh(easy_redeem.as_bytes()).as_bytes().to_lower_hex_string(),
        "destination_script_pubkey_hex": destination.as_bytes().to_lower_hex_string(),
        "pool_before_hex": pool_before.to_lower_hex_string(),
        "pool_after_hex": pool_after.to_lower_hex_string(),
        "results": rows,
    })
}

fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    assert_eq!(
        args.len(),
        3,
        "usage: binohash_codesep_fixtures FUNDING_TXID DESTINATION_SCRIPT_HEX"
    );
    let funding_txid = Txid::from_str(&args[1]).expect("funding txid");
    let destination = ScriptBuf::from_bytes(Vec::from_hex(&args[2]).expect("destination hex"));
    println!("{}", generate(funding_txid, destination));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operative_and_dead_boundaries_produce_distinct_signed_digests() {
        let txid = Txid::from_str(&"00".repeat(32)).unwrap();
        let fixture = generate(txid, ScriptBuf::from_bytes(vec![0x51]));
        assert_eq!(fixture["results"].as_array().unwrap().len(), 2);
        assert!(fixture["redeem_script_bytes"].as_u64().unwrap() <= 520);
        assert!(
            fixture["operative_codesep_offset"].as_u64().unwrap()
                < fixture["dead_codesep_offset"].as_u64().unwrap()
        );
    }
}
