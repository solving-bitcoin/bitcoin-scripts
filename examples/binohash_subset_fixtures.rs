//! Reduced single-round Binohash subset fixture for pinned Bitcoin Core.
//!
//! Raw legacy bytecode is intentional: embedded signature pushes and OP_ROLL
//! are the consensus behavior under test. Public deterministic test keys and
//! preimages do not provide the paper's work or collision-security bounds.

use bitcoin::{
    absolute,
    consensus::serialize,
    hashes::{hash160, Hash},
    hex::{DisplayHex, FromHex},
    secp256k1::{Message, PublicKey, Secp256k1, SecretKey},
    transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use bitcoin_lab::introspection::binohash::{binohash_digest, push_data};
use serde_json::{json, Value};
use std::str::FromStr;

const INPUT_VALUE: u64 = 1_000_000;
const FEE: u64 = 20_000;
const MAX_PUZZLE_SIGNATURE_BYTES: usize = 71;
const PAIRS: [(usize, usize); 3] = [(0, 1), (0, 2), (1, 2)];

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

fn selector(index: usize) -> u8 {
    match index {
        0 => 0x00,
        1 => 0x51,
        2 => 0x52,
        _ => panic!("invalid selector"),
    }
}

fn script_sig(puzzle: &[u8], preimage: &[u8], pair: (usize, usize), redeem: &[u8]) -> ScriptBuf {
    script_sig_with_indices(
        puzzle,
        preimage,
        &[selector(pair.0)],
        &[selector(pair.1)],
        redeem,
    )
}

fn script_sig_with_indices(
    puzzle: &[u8],
    preimage: &[u8],
    first_index_push: &[u8],
    second_index_push: &[u8],
    redeem: &[u8],
) -> ScriptBuf {
    ScriptBuf::from_bytes(
        [
            vec![0x00], // CHECKMULTISIG dummy
            push_data(puzzle),
            push_data(preimage),
            first_index_push.to_vec(),
            second_index_push.to_vec(),
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

fn redeem_script(
    pool: &[Vec<u8>; 3],
    puzzle_pubkey: &[u8],
    pool_pubkey: &[u8],
    hashes: &[[u8; 20]; 3],
) -> ScriptBuf {
    let mut s = Vec::new();
    // Initial stack: dummy, puzzle signature, preimage, i, j.
    // Save the preimage, require canonical i<j in {0,1,2}, then save i,j.
    s.extend([0x7b, 0x6b]); // ROT TOALTSTACK
    s.extend([0x6e, 0x7c, 0x76, 0x00, 0x87, 0x7c, 0x51, 0x87, 0x9b, 0x69]);
    s.extend([0x76, 0x51, 0x87, 0x7c, 0x52, 0x87, 0x9b, 0x69]);
    s.extend([0x6e, 0x9f, 0x69, 0x6e, 0x6b, 0x6b]); // 2DUP LESSTHAN VERIFY; save j,i
    for signature in pool {
        s.extend(push_data(signature));
    }
    // With three pool items, j is at depth 3; roll depth (2-j), save S_j.
    // With two remaining pool items, i is at depth 3; roll depth (1-i).
    s.extend([0x53, 0x79, 0x52, 0x7c, 0x94, 0x7a, 0x6b]);
    s.extend([0x53, 0x79, 0x51, 0x7c, 0x94, 0x7a, 0x6b]);
    s.extend([0x75, 0x6d, 0x6c, 0x6c]); // discard unused pool sig and indices; restore S_i,S_j
                                        // The puzzle signature is now depth 2. Its byte length is the toy puzzle.
    s.extend([0x52, 0x79, 0x82]); // 2 PICK SIZE
    s.extend(push_data(&[MAX_PUZZLE_SIGNATURE_BYTES as u8]));
    s.extend([0xa1, 0x69, 0x75]); // LESSTHANOREQUAL VERIFY DROP
    s.push(0x53); // 3 signatures: puzzle, S_i, S_j
    s.extend(push_data(puzzle_pubkey));
    for _ in 0..3 {
        s.extend(push_data(pool_pubkey));
    }
    s.extend([0x54, 0xaf]); // 4 pubkeys; CHECKMULTISIGVERIFY
                            // The selected indices survived on altstack. Their sum uniquely identifies
                            // the three pairs and selects a hardcoded preimage commitment.
    s.extend([0x6c, 0x6c, 0x93]); // FROMALTSTACK FROMALTSTACK ADD
    s.extend([0x76, 0x51, 0x87, 0x63, 0x75]); // if sum == 1
    s.extend(push_data(&hashes[0]));
    s.extend([0x67, 0x76, 0x52, 0x87, 0x63, 0x75]); // else if sum == 2
    s.extend(push_data(&hashes[1]));
    s.extend([0x67, 0x53, 0x88]); // else require sum == 3
    s.extend(push_data(&hashes[2]));
    s.extend([0x68, 0x68, 0x6c, 0xa9, 0x87]); // ENDIF ENDIF, preimage HASH160 EQUAL
    ScriptBuf::from_bytes(s)
}

fn generate(funding_txid: Txid, destination: ScriptBuf, easy_vout: u32, bino_vout: u32) -> Value {
    let secp = Secp256k1::new();
    let pool_key = SecretKey::from_slice(&[1; 32]).unwrap();
    let puzzle_key = SecretKey::from_slice(&[2; 32]).unwrap();
    let pool_pubkey = PublicKey::from_secret_key(&secp, &pool_key).serialize();
    let puzzle_pubkey = PublicKey::from_secret_key(&secp, &puzzle_key).serialize();
    let mut bug_digest = [0_u8; 32];
    bug_digest[0] = 1;
    let pool: [Vec<u8>; 3] = std::array::from_fn(|index| {
        let mut nonce_data = [0_u8; 32];
        nonce_data[0] = index as u8 + 1;
        let mut signature = secp
            .sign_ecdsa_with_noncedata(&Message::from_digest(bug_digest), &pool_key, &nonce_data)
            .serialize_der()
            .to_vec();
        signature.push(0x03); // SIGHASH_SINGLE bug: input 1, only one output
        signature
    });
    assert!(pool[0] != pool[1] && pool[0] != pool[2] && pool[1] != pool[2]);
    let preimages: [Vec<u8>; 3] = std::array::from_fn(|index| vec![index as u8 + 11; 16]);
    let hashes: [[u8; 20]; 3] =
        std::array::from_fn(|index| hash160::Hash::hash(&preimages[index]).to_byte_array());
    let redeem = redeem_script(&pool, &puzzle_pubkey, &pool_pubkey, &hashes);
    assert!(
        redeem.len() <= 520,
        "toy subset redeemScript exceeds P2SH limit: {}",
        redeem.len()
    );
    let easy_redeem = ScriptBuf::from_bytes(vec![0x51]);
    let mut tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![
            input(funding_txid, easy_vout),
            input(funding_txid, bino_vout),
        ],
        output: vec![TxOut {
            value: Amount::from_sat(2 * INPUT_VALUE - FEE),
            script_pubkey: destination.clone(),
        }],
    };
    tx.input[0].script_sig = ScriptBuf::from_bytes(push_data(easy_redeem.as_bytes()));
    let rows: Vec<Value> = PAIRS
        .iter()
        .enumerate()
        .map(|(pair_index, &(i, j))| {
            let digest = binohash_digest(&tx, 1, &redeem, &pool, &[i, j], 0x01).unwrap();
            let mut puzzle = secp
                .sign_ecdsa(&Message::from_digest(digest), &puzzle_key)
                .serialize_der()
                .to_vec();
            puzzle.push(0x01);
            let mut candidate = tx.clone();
            candidate.input[1].script_sig =
                script_sig(&puzzle, &preimages[pair_index], (i, j), redeem.as_bytes());
            let mut wrong_preimage = candidate.clone();
            wrong_preimage.input[1].script_sig = script_sig(
                &puzzle,
                &preimages[(pair_index + 1) % PAIRS.len()],
                (i, j),
                redeem.as_bytes(),
            );
            let mut wrong_indices = candidate.clone();
            wrong_indices.input[1].script_sig = script_sig(
                &puzzle,
                &preimages[(pair_index + 1) % PAIRS.len()],
                PAIRS[(pair_index + 1) % PAIRS.len()],
                redeem.as_bytes(),
            );
            let mut reversed_indices = candidate.clone();
            reversed_indices.input[1].script_sig =
                script_sig(&puzzle, &preimages[pair_index], (j, i), redeem.as_bytes());
            let mut duplicate_indices = candidate.clone();
            duplicate_indices.input[1].script_sig =
                script_sig(&puzzle, &preimages[pair_index], (j, j), redeem.as_bytes());
            let mut out_of_range_index = candidate.clone();
            out_of_range_index.input[1].script_sig = script_sig_with_indices(
                &puzzle,
                &preimages[pair_index],
                &[selector(i)],
                &[0x53], // canonical 3, outside the three-signature pool
                redeem.as_bytes(),
            );
            let mut noncanonical_index = candidate.clone();
            noncanonical_index.input[1].script_sig = script_sig_with_indices(
                &puzzle,
                &preimages[pair_index],
                &push_data(&[0x80]), // noncanonical negative zero
                &[selector(j)],
                redeem.as_bytes(),
            );
            let mut large_puzzle = None;
            for nonce in 1..=255_u8 {
                let mut nonce_data = [0_u8; 32];
                nonce_data[0] = nonce;
                let signature = secp.sign_ecdsa_with_noncedata(
                    &Message::from_digest(digest),
                    &puzzle_key,
                    &nonce_data,
                );
                let mut bytes = signature.serialize_der().to_vec();
                bytes.push(0x01);
                if bytes.len() > MAX_PUZZLE_SIGNATURE_BYTES {
                    secp.verify_ecdsa(
                        &Message::from_digest(digest),
                        &signature,
                        &PublicKey::from_secret_key(&secp, &puzzle_key),
                    )
                    .unwrap();
                    large_puzzle = Some(bytes);
                    break;
                }
            }
            let large_puzzle = large_puzzle.expect("no deterministic oversized valid signature");
            let mut wrong_size = candidate.clone();
            wrong_size.input[1].script_sig = script_sig(
                &large_puzzle,
                &preimages[pair_index],
                (i, j),
                redeem.as_bytes(),
            );
            json!({
                "pair": [i, j],
                "preimage_hex": preimages[pair_index].to_lower_hex_string(),
                "local_digest_hex": digest.to_lower_hex_string(),
                "puzzle_signature_hex": puzzle.to_lower_hex_string(),
                "puzzle_signature_bytes": puzzle.len(),
                "passes_size_filter": puzzle.len() <= MAX_PUZZLE_SIGNATURE_BYTES,
                "transaction": transaction_record(&candidate),
                "wrong_preimage": transaction_record(&wrong_preimage),
                "wrong_indices": transaction_record(&wrong_indices),
                "reversed_indices": transaction_record(&reversed_indices),
                "duplicate_indices": transaction_record(&duplicate_indices),
                "out_of_range_index": transaction_record(&out_of_range_index),
                "noncanonical_index": transaction_record(&noncanonical_index),
                "wrong_size": transaction_record(&wrong_size),
                "oversized_valid_puzzle_signature_hex": large_puzzle.to_lower_hex_string(),
            })
        })
        .collect();
    assert_ne!(rows[0]["local_digest_hex"], rows[1]["local_digest_hex"]);
    assert_ne!(rows[0]["local_digest_hex"], rows[2]["local_digest_hex"]);
    assert_ne!(rows[1]["local_digest_hex"], rows[2]["local_digest_hex"]);
    json!({
        "experiment": "binohash-legacy-2-of-3-toy",
        "funding_txid": funding_txid.to_string(),
        "easy_vout": easy_vout,
        "binohash_vout": bino_vout,
        "input_value_sat": INPUT_VALUE,
        "fee_sat": FEE,
        "max_puzzle_signature_bytes": MAX_PUZZLE_SIGNATURE_BYTES,
        "redeem_script_hex": redeem.as_bytes().to_lower_hex_string(),
        "redeem_script_bytes": redeem.len(),
        "binohash_script_pubkey_hex": p2sh(redeem.as_bytes()).as_bytes().to_lower_hex_string(),
        "easy_script_pubkey_hex": p2sh(easy_redeem.as_bytes()).as_bytes().to_lower_hex_string(),
        "destination_script_pubkey_hex": destination.as_bytes().to_lower_hex_string(),
        "pool_signatures_hex": pool.iter().map(|sig| sig.to_lower_hex_string()).collect::<Vec<_>>(),
        "preimage_hashes_hex": hashes.iter().map(|hash| hash.to_lower_hex_string()).collect::<Vec<_>>(),
        "results": rows,
    })
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert!(
        args.len() == 3 || args.len() == 5,
        "usage: binohash_subset_fixtures FUNDING_TXID DESTINATION_SCRIPT_HEX [EASY_VOUT BINO_VOUT]"
    );
    let funding_txid = Txid::from_str(&args[1]).expect("funding txid");
    let destination = ScriptBuf::from_bytes(Vec::from_hex(&args[2]).expect("destination hex"));
    let (easy_vout, bino_vout) = if args.len() == 5 {
        (args[3].parse().unwrap(), args[4].parse().unwrap())
    } else {
        (0, 1)
    };
    println!(
        "{}",
        generate(funding_txid, destination, easy_vout, bino_vout)
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn three_subsets_have_distinct_digests_and_fit_p2sh() {
        let txid = Txid::from_str(&"00".repeat(32)).unwrap();
        let fixture = generate(txid, ScriptBuf::from_bytes(vec![0x51]), 0, 1);
        assert_eq!(fixture["results"].as_array().unwrap().len(), 3);
        assert!(fixture["redeem_script_bytes"].as_u64().unwrap() <= 520);
    }
}
