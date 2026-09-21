//! Compile exact-60, pairwise-byte-distinct signature diagnostics.
//! The supplied key is a public fixture; no private key is read or generated.
use bitcoin::{script::Instruction, secp256k1::PublicKey, ScriptBuf};
use bitcoin_lab::{signatures::pointlocks, support::{provenance, script::{script, ScriptCompilation}}};
use serde_json::json;
use std::str::FromStr;

fn predicate(key: &[u8], count: usize) -> ScriptBuf {
    script! {
        // All signature operands coexist. Check every pair before consuming any.
        for i in 0..count {
            for j in i+1..count {
                {i} OP_PICK {j+1} OP_PICK OP_EQUAL OP_NOT OP_VERIFY
            }
        }
        {key.to_vec()} OP_TOALTSTACK
        for _ in 0..count {
            OP_SIZE 60 OP_EQUALVERIFY
            OP_FROMALTSTACK OP_DUP OP_TOALTSTACK OP_CHECKSIGVERIFY
        }
        OP_FROMALTSTACK OP_DROP OP_TRUE
    }.compile_with_policy()
}

fn main() {
    let key = PublicKey::from_str(&std::env::args().nth(1).expect("compressed public key hex")).unwrap();
    let rows: Vec<_> = [1, 2, 6, 8].into_iter().map(|count| {
        let script = if count == 1 {
            pointlocks::g_half_point_lock(key).compile_with_policy()
        } else {
            predicate(&key.serialize(), count)
        };
        let ops = script.instructions().filter(|v| matches!(v, Ok(Instruction::Op(op)) if op.to_u8() > 0x60)).count();
        assert!(script.len() <= 520 && ops <= 201);
        json!({"count": count, "predicate": if count == 1 { "existing-max60-small-r" } else { "all-pairs-distinct-exact60" }, "script_hex": script.to_hex_string(),
            "script_bytes": script.len(), "static_non_push_opcodes": ops,
            "sigops": count, "hint_items": 0, "redeem_entry_items": count,
            "script_sig_push_items": count+1})
    }).collect();
    println!("{}", serde_json::to_string_pretty(&json!({
        "scope": "Compiled same-key, same-scriptCode, exact60, all-pairs byte-inequality predicate. Native witness validity is checked by the separate Python/Core runner.",
        "compiler_commit": provenance::compiler().unwrap().commit,
        "interpreter_commit": provenance::interpreter().unwrap().commit,
        "rows": rows
    })).unwrap());
}
