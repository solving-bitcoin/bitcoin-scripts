//! Static, policy-compiled resource profile of Binohash paper Appendix B.1.
//!
//! The embedded 9-byte values are distinct DER-shaped placeholders, not
//! recovered ECDSA signatures. This measures a single-round locking script;
//! it does not execute or establish consensus validity for the full protocol.

use bitcoin::{
    script::Instruction,
    secp256k1::{PublicKey, Secp256k1, SecretKey},
};
use bitcoin_lab::support::script::{script, ScriptCompilation};
use serde_json::{json, Value};

fn profile(n: usize, t: usize) -> Value {
    assert!(t > 0 && t <= n && n <= 151);
    let hashes: Vec<Vec<u8>> = (0..n).map(|i| vec![i as u8; 20]).collect();
    let signatures: Vec<Vec<u8>> = (0..n)
        .map(|i| {
            vec![
                0x30,
                0x06,
                0x02,
                0x01,
                (i % 127) as u8 + 1,
                0x02,
                0x01,
                (i / 127) as u8 + 1,
                0x01,
            ]
        })
        .collect();
    let secp = Secp256k1::new();
    let puzzle_pubkey =
        PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[1; 32]).unwrap())
            .serialize()
            .to_vec();
    let locking = script! {
        for hash in hashes.iter().rev() { { hash.clone() } }
        for signature in signatures.iter().rev() { { signature.clone() } }
        OP_0
        for i in 0..t {
            { 2 * n - i } OP_ROLL
            { n - i } OP_MIN
            OP_DUP
            { n + 1 } OP_ADD OP_ROLL
            { 2 * n + t - 2 * i } OP_ROLL
            OP_HASH160 OP_EQUALVERIFY OP_ROLL
        }
        { 2 * n + 1 } OP_ROLL
        OP_SIZE { 55 } OP_EQUALVERIFY
        { t + 1 }
        for _ in 0..t { { 2 * n + 2 } OP_ROLL }
        { puzzle_pubkey }
        { t + 1 } OP_CHECKMULTISIG
    };
    let compiled = locking.compile_with_policy();
    let mut non_push_opcodes = 0;
    let mut pushbyte_instructions = 0;
    for instruction in compiled.instructions() {
        match instruction.expect("policy-produced Appendix B script must parse") {
            Instruction::Op(opcode) if opcode.to_u8() > 0x60 => non_push_opcodes += 1,
            Instruction::PushBytes(_) => pushbyte_instructions += 1,
            _ => {}
        }
    }
    // Core charges one additional opcode per pubkey when CHECKMULTISIG runs.
    // The actual execution path has not been validated for this static script.
    let core_opcode_count_if_multisig_reached = non_push_opcodes + t + 1;
    let paper_estimate = (t == 8).then_some(244 + 31 * n);
    json!({
        "n": n,
        "t": t,
        "rounds": 1,
        "execution": "unclassified",
        "evidence": "locally-reproduced",
        "policy_compiled_locking_script_bytes": compiled.len(),
        "non_push_opcodes": non_push_opcodes,
        "core_opcode_count_if_multisig_reached": core_opcode_count_if_multisig_reached,
        "embedded_signature_bytes": n * 10,
        "embedded_hash_bytes": n * 21,
        "remaining_script_bytes_including_puzzle_key_and_optimizer_delta": compiled.len() - 31 * n,
        "serialized_pushbyte_instructions": pushbyte_instructions,
        "under_10000_byte_limit": compiled.len() <= 10_000,
        "under_201_core_opcode_limit_if_multisig_reached": core_opcode_count_if_multisig_reached <= 201,
        "fits_p2sh_redeem_520_bytes": compiled.len() <= 520,
        "paper_estimated_one_round_bytes_without_pinning": paper_estimate,
        "policy_bytes_minus_paper_estimate": paper_estimate.map(|estimate| compiled.len() as i64 - estimate as i64),
    })
}

fn main() {
    println!(
        "{}",
        json!({
            "experiment": "binohash-appendix-b-single-round-static",
            "source_pdf": "https://robinlinus.com/binohash.pdf",
            "source_pdf_sha256": "1be2b63034a86db1f9f4a35c7963248d307583723079ff25284a9fc4affee94a",
            "source_section": "Appendix B.1",
            "core_opcode_source_commit": "49faec4f87f5cd19c88db01a82e5c68b087c8227",
            "compilation": "ScriptCompilation::compile_with_policy; CompileOptions::ALL below 32 KiB",
            "configurations": [profile(10, 5), profile(120, 8), profile(147, 8), profile(151, 8)],
        })
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_profiles_parse_and_preserve_embedding_counts() {
        for (n, t, bytes, charged) in [
            (10, 5, 444, 60),
            (120, 8, 3950, 93),
            (147, 8, 4803, 93),
            (151, 8, 4927, 93),
        ] {
            let row = profile(n, t);
            assert_eq!(row["embedded_signature_bytes"], n * 10);
            assert_eq!(row["embedded_hash_bytes"], n * 21);
            assert_eq!(row["policy_compiled_locking_script_bytes"], bytes);
            assert_eq!(row["non_push_opcodes"], 10 * t + 4);
            assert_eq!(row["core_opcode_count_if_multisig_reached"], charged);
            assert_eq!(row["execution"], "unclassified");
        }
    }

    #[test]
    fn checked_report_matches_policy_compiled_scripts() {
        let report: Value = serde_json::from_str(include_str!(
            "../tests/data/binohash-appendix-b-resources.json"
        ))
        .unwrap();
        assert_eq!(report["source_section"], "Appendix B.1");
        assert_eq!(
            report["configurations"],
            json!([
                profile(10, 5),
                profile(120, 8),
                profile(147, 8),
                profile(151, 8)
            ])
        );
    }
}
