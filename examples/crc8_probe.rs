//! Private prototype: production source remains unchanged.
use bitcoin::{
    consensus::encode::serialize,
    hashes::{sha256, Hash},
    script::Instruction,
    ScriptBuf, Witness,
};
use bitcoin_lab::{
    arithmetic::{
        scriptint::mul_by_constant,
        u4::{
            logic::{
                u4_drop_half_lookup, u4_drop_half_table, u4_half_table_operation,
                u4_push_half_lookup, u4_push_half_xor_table,
            },
            stack::u4_drop,
        },
    },
    support::{
        execution::ExecuteInfo,
        provenance,
        script::*,
        tapscript::{execute_tapscript, TapscriptOutcome, TapscriptProfile},
    },
};
use bitcoin_scriptexec::ExecError;
use serde_json::{json, Value};

fn reduce(mut x: u16) -> u8 {
    for bit in (8..16).rev() {
        if x & (1 << bit) != 0 {
            x ^= 0x107 << (bit - 8);
        }
    }
    x as u8
}
// Independent polynomial remainder of the message times x^8.
fn oracle(digits: &[u8], initial: u8) -> u8 {
    let mut c = initial;
    for &d in digits {
        assert!(d < 16);
        c = reduce((u16::from(c) << 4) ^ (u16::from(d) << 8));
    }
    c
}
fn guard() -> Script {
    script! {OP_DUP 0 OP_GREATERTHANOREQUAL OP_VERIFY OP_DUP 16 OP_LESSTHAN OP_VERIFY}
}
const TABLE_ITEMS: u32 = 136 + 16 + 32;
fn feedback(count: u32, initial: u8) -> Script {
    if count == 0 {
        return script! {{initial}};
    }
    script! {
        {u4_push_half_xor_table()} {u4_push_half_lookup()}
        for i in (0u16..16).rev() { {reduce(i<<8)>>4} {reduce(i<<8)&15} }
        {initial>>4} {initial&15}
        for _ in 0..count {
            {TABLE_ITEMS+2} OP_ROLL {guard()}
            // H L d -> L d H -> L (H xor d).
            OP_ROT {u4_half_table_operation(35)}
            OP_DUP OP_ADD OP_DUP 2 OP_ADD OP_PICK OP_SWAP 3 OP_ADD OP_PICK
            // L Tlow Thigh -> Tlow (L xor Thigh) -> newH newL.
            OP_ROT {u4_half_table_operation(35)} OP_SWAP
        }
        OP_SWAP {mul_by_constant(16)} OP_ADD OP_TOALTSTACK
        {u4_drop(32)} {u4_drop_half_lookup()} {u4_drop_half_table()}
        OP_FROMALTSTACK
    }
}
fn bit_step() -> Script {
    script! {
        // b0..b7 d -> b0..b6 f; f = b7 xor d.
        OP_NUMNOTEQUAL
        7 OP_ROLL OP_OVER OP_NUMNOTEQUAL
        7 OP_ROLL 2 OP_PICK OP_NUMNOTEQUAL
        for _ in 0..5 {7 OP_ROLL}
    }
}
fn serial(count: u32, initial: u8) -> Script {
    serial_with_step(count, initial, bit_step())
}
fn serial_with_step(count: u32, initial: u8, step: Script) -> Script {
    script! {
        for bit in 0..8 { {(initial>>bit)&1} }
        for _ in 0..count {
            8 OP_ROLL {guard()}
            for weight in [8,4,2,1] {
                OP_DUP {weight} OP_GREATERTHANOREQUAL OP_TUCK
                OP_IF {weight} OP_SUB OP_ENDIF
            }
            OP_DROP
            for _ in 0..4 {OP_TOALTSTACK}
            for _ in 0..4 {OP_FROMALTSTACK {step.clone()}}
        }
        for _ in 0..7 {OP_DUP OP_ADD OP_ADD}
    }
}
type Family = (&'static str, fn(u32, u8) -> Script);
const FAMILIES: [Family; 2] = [("nibble-feedback", feedback), ("serial-bits", serial)];
fn num(x: i64) -> Vec<u8> {
    let mut b = [0; 8];
    let n = bitcoin::script::write_scriptint(&mut b, x);
    b[..n].to_vec()
}
// First logical nibble is on top; each byte contributes its high nibble first.
fn witness(d: &[u8]) -> Vec<Vec<u8>> {
    d.iter().rev().map(|&x| num(x.into())).collect()
}
fn sha(b: &[u8]) -> String {
    sha256::Hash::hash(b).to_string()
}
fn encoded(w: &[Vec<u8>]) -> Vec<u8> {
    serialize(&Witness::from_slice(w))
}
fn run(s: ScriptBuf, w: Vec<Vec<u8>>) -> ExecuteInfo {
    match execute_tapscript(s, w, TapscriptProfile::Consensus).outcome {
        TapscriptOutcome::Executed(r) => r,
        o => panic!("unexpected {o:?}"),
    }
}
fn output(r: &ExecuteInfo, q: u8) {
    assert!(r.stack_limit_enforced);
    assert_eq!(r.error, None, "{r}");
    assert_eq!(r.final_stack.len(), 1, "{r}");
    assert_eq!(r.final_stack.get(0), num(q.into()));
}
fn clean(r: &ExecuteInfo) {
    output(r, 1);
    assert!(r.success);
}
fn rejects(r: &ExecuteInfo, e: ExecError) {
    assert!(r.stack_limit_enforced);
    assert_eq!(r.error, Some(e), "{r}");
    assert!(!r.success);
}
fn caught(r: &ExecuteInfo, e: ExecError) {
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| rejects(r, e))).is_err());
}
fn leaf(g: Script, q: u8) -> Script {
    script! {{g}{q} OP_EQUALVERIFY OP_TRUE}
}
fn artifact(g: Script, w: &[Vec<u8>]) -> Value {
    let raw = g.len();
    let opts = if raw <= 32768 { "ALL" } else { "NONE" };
    let s = g.compile_with_policy();
    let nonpush = s
        .instructions()
        .map(|i| matches!(i.unwrap(), Instruction::Op(op) if op.to_u8()>0x60) as u64)
        .sum::<u64>();
    let hash = sha(s.as_bytes());
    let bytes = s.len();
    let r = run(s, w.to_vec());
    let out: Vec<Vec<u8>> = (0..r.final_stack.len())
        .map(|i| r.final_stack.get(i))
        .collect();
    json!({"raw_script_bytes":raw,"compilation_options":opts,"script_bytes":bytes,"script_sha256":hash,"static_non_push_opcodes":nonpush,"max_combined_stack_items":r.stats.max_nb_stack_items,"error":r.error.map(|e|format!("{e:?}")),"clean_success":r.success && r.final_stack.len()==1,"output_items":out.len(),"output_sha256":sha(&encoded(&out)),"executed_opcodes":null,"complete_validation_budget":null,"charged_sig_budget":r.stats.start_validation_weight-r.stats.validation_weight,"stack_limit_enforced":r.stack_limit_enforced})
}
fn mutate_guard(s: &ScriptBuf) -> ScriptBuf {
    let pattern = guard().compile_with_policy();
    let mut out = Vec::new();
    let mut i = 0;
    let mut found = 0;
    while i < s.len() {
        if s.as_bytes()[i..].starts_with(pattern.as_bytes()) {
            i += pattern.len();
            found += 1;
        } else {
            out.push(s.as_bytes()[i]);
            i += 1;
        }
    }
    assert_eq!(found, 4);
    ScriptBuf::from_bytes(out)
}
fn caller_wrapper(g: Script, q: u8, main: &[Vec<u8>], alt: &[Vec<u8>]) -> Script {
    script! {
        for a in alt { {a.clone()} OP_TOALTSTACK }
        {g}{q} OP_EQUALVERIFY
        for m in main.iter().rev() { {m.clone()} OP_EQUALVERIFY }
        for a in alt.iter().rev() { OP_FROMALTSTACK {a.clone()} OP_EQUALVERIFY }
        OP_TRUE
    }
}
fn sources() -> Value {
    let mut obj = serde_json::Map::new();
    for p in [
        "examples/crc8_probe.rs",
        "research/crc8-nibble-feedback/verify_probe.py",
        "src/arithmetic/u4/logic.rs",
        "src/arithmetic/u4/stack.rs",
        "src/arithmetic/scriptint/mod.rs",
        "src/support/script.rs",
        "src/support/execution.rs",
        "src/support/tapscript.rs",
        "src/support/provenance.rs",
        "Cargo.lock",
    ] {
        obj.insert(p.into(), json!(sha(&std::fs::read(p).unwrap())));
    }
    Value::Object(obj)
}
fn main() {
    let revision = std::env::args().nth(1).expect("source revision required");
    assert_eq!(revision.len(), 40);
    assert!(revision.bytes().all(|b| b.is_ascii_hexdigit()));
    let mut rows = Vec::new();
    let mut exhaustive = Vec::new();
    let mut frontiers = Vec::new();
    // Reproduce the first private reference's extra-feedback-copy error.
    // The same exact-result assertion passes the corrected schedule and catches
    // the original step; this is not a defect in existing production source.
    let original_bad_step = script! {
        OP_NUMNOTEQUAL
        OP_DUP 8 OP_ROLL OP_OVER OP_NUMNOTEQUAL
        7 OP_ROLL 2 OP_PICK OP_NUMNOTEQUAL
        for _ in 0..5 {7 OP_ROLL}
    };
    let valid_reference = serial(1, 0);
    let bad_reference = serial_with_step(1, 0, original_bad_step);
    output(
        &run(valid_reference.clone().compile_with_policy(), witness(&[0])),
        0,
    );
    let bad_result = run(bad_reference.clone().compile_with_policy(), witness(&[0]));
    assert_eq!(bad_result.error, None);
    assert_eq!(bad_result.final_stack.len(), 5);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| output(&bad_result, 0))).is_err()
    );
    let regression = json!({"input_nibbles":[0],"initial_crc":0,"expected_crc":0,"valid_fragment":artifact(valid_reference,&witness(&[0])),"original_bad_step_fragment":artifact(bad_reference,&witness(&[0]))});
    let digits: Vec<u8> = b"123456789"
        .iter()
        .flat_map(|&b| [b >> 4, b & 15])
        .collect();
    assert_eq!(oracle(&digits, 0), 0xf4);
    for (name, gen) in FAMILIES {
        // All states and every nibble exercise the complete transition domain.
        let mut transition_outputs = Vec::new();
        for state in 0..=255u8 {
            let s = gen(1, state).compile_with_policy();
            for d in 0..16 {
                let q = oracle(&[d], state);
                output(&run(s.clone(), witness(&[d])), q);
                transition_outputs.push(q);
            }
        }
        let s = gen(4, 0).compile_with_policy();
        let mut stream = Vec::new();
        for x in 0..=65535u32 {
            let d = [
                (x >> 12) as u8,
                ((x >> 8) & 15) as u8,
                ((x >> 4) & 15) as u8,
                (x & 15) as u8,
            ];
            let q = oracle(&d, 0);
            output(&run(s.clone(), witness(&d)), q);
            stream.push(q);
        }
        exhaustive.push(json!({"family":name,"transition_cases":4096,"transition_output_sha256":sha(&transition_outputs),"two_byte_cases":65536,"two_byte_output_sha256":sha(&stream)}));
        for n in [0, 1, 2, 4, 18, 32, 128, 256] {
            for pattern in ["zero", "varied"] {
                let d: Vec<u8> = if n == 18 && pattern == "varied" {
                    digits.clone()
                } else {
                    (0..n)
                        .map(|i| {
                            if pattern == "zero" {
                                0
                            } else {
                                ((i * 7 + 3) % 16) as u8
                            }
                        })
                        .collect()
                };
                let q = oracle(&d, 0);
                let w = witness(&d);
                let g = gen(n, 0);
                output(&run(g.clone().compile_with_policy(), w.clone()), q);
                clean(&run(leaf(g.clone(), q).compile_with_policy(), w.clone()));
                rows.push(json!({"family":name,"nibble_count":n,"pattern":pattern,"logical_nibbles":d,"initial_crc":0,"expected_crc":q,"data_items":w.len(),"hint_items":0,"hint_bytes":0,"all_data_at_entry":true,"witness_bytes":encoded(&w).len(),"witness_sha256":sha(&encoded(&w)),"fragment":artifact(g.clone(),&w),"checked_leaf":artifact(leaf(g,q),&w)}));
            }
        }
        // Same typed-error harness, valid cleanup, every live input position.
        let zero = [0u8; 4];
        clean(&run(
            leaf(gen(4, 0), 0).compile_with_policy(),
            witness(&zero),
        ));
        for position in 0..4 {
            for (bad, e) in [
                (num(-1), ExecError::Verify),
                (num(16), ExecError::Verify),
                (vec![0; 5], ExecError::ScriptIntNumericOverflow),
                (vec![0; 80], ExecError::ScriptIntNumericOverflow),
                (vec![0; 81], ExecError::ScriptIntNumericOverflow),
                (vec![0; 520], ExecError::ScriptIntNumericOverflow),
                (vec![0; 521], ExecError::PushSize),
            ] {
                let mut w = witness(&zero);
                w[position] = bad;
                rejects(&run(leaf(gen(4, 0), 0).compile_with_policy(), w), e);
            }
            let mut d = zero;
            if name == "serial-bits" {
                d[3 - position] = 15;
            }
            let q = oracle(&d, 0);
            let checked = leaf(gen(4, 0), q).compile_with_policy();
            clean(&run(checked.clone(), witness(&d)));
            let mut w = witness(&d);
            w[position] = num(16);
            rejects(&run(checked.clone(), w.clone()), ExecError::Verify);
            let mutant = mutate_guard(&checked);
            clean(&run(mutant.clone(), witness(&d)));
            clean(&run(mutant.clone(), w.clone()));
            caught(&run(mutant, w), ExecError::Verify);
        }
        for missing in 1..=4 {
            rejects(
                &run(
                    leaf(gen(4, 0), 0).compile_with_policy(),
                    vec![vec![]; 4 - missing],
                ),
                ExecError::InvalidStackOperation,
            );
        }
        for alias in [vec![0], vec![0x80], vec![1, 0], vec![15, 0, 0, 0]] {
            let x = bitcoin::script::read_scriptint_non_minimal(&alias).unwrap() as u8;
            let d = [x; 4];
            clean(&run(
                leaf(gen(4, 0), oracle(&d, 0)).compile_with_policy(),
                vec![alias; 4],
            ));
        }
        // Full observable caller state at the exact measured stack frontier.
        let d: Vec<u8> = (0..32).map(|i| ((i * 7 + 3) % 16) as u8).collect();
        let q = oracle(&d, 0);
        let w = witness(&d);
        let g = gen(32, 0);
        let peak = run(g.clone().compile_with_policy(), w.clone())
            .stats
            .max_nb_stack_items as usize;
        for alt_count in [0, 3] {
            let preserved = 1000 - peak - alt_count;
            let main: Vec<Vec<u8>> = (0..preserved)
                .map(|i| vec![0x70, (i & 255) as u8, (i >> 8) as u8])
                .collect();
            let alt: Vec<Vec<u8>> = (0..alt_count).map(|i| vec![0x90, i as u8]).collect();
            let mut all = main.clone();
            all.extend(w.clone());
            let wrapper = caller_wrapper(g.clone(), q, &main, &alt);
            let accepted = run(wrapper.clone().compile_with_policy(), all.clone());
            clean(&accepted);
            assert_eq!(accepted.stats.max_nb_stack_items, 1000);
            all.insert(0, vec![0x55]);
            rejects(
                &run(wrapper.compile_with_policy(), all),
                ExecError::StackSize,
            );
        }
        let max = 1000 - (peak - 32);
        let long: Vec<u8> = (0..max).map(|i| ((i * 7 + 3) % 16) as u8).collect();
        let longq = oracle(&long, 0);
        let a = artifact(leaf(gen(max as u32, 0), longq), &witness(&long));
        assert_eq!(a["error"], Value::Null);
        assert_eq!(a["max_combined_stack_items"], 1000);
        let over = vec![0; max + 1];
        let b = artifact(leaf(gen((max + 1) as u32, 0), 0), &witness(&over));
        assert_eq!(b["error"], "StackSize");
        assert_eq!(b["max_combined_stack_items"], 1001);
        frontiers.push(json!({"family":name,"max_nibbles":max,"data_items":max,"hint_items":0,"all_data_at_entry":true,"allowed_witness_bytes_max":5*max+if max>=253 {3} else {1},"fixture_crc":longq,"fixture_witness_bytes":encoded(&witness(&long)).len(),"accepted_leaf":a,"one_more_leaf":b}));
    }
    println!("{}",serde_json::to_string_pretty(&json!({"source_revision":revision,"source_sha256":sources(),"compiler_source":provenance::compiler().unwrap().source,"interpreter_source":provenance::interpreter().unwrap().source,"profile":{"context":"tapscript","minimal_numbers":false,"minimal_if":true,"stack_limit":true,"op_cat":false,"cltv":true,"csv":true,"synthetic_empty_transaction":true,"data_only_budget":true,"signatures":0},"classification":{"evidence":"locally-reproduced","execution":"unclassified"},"polynomial":"0x107","initial_crc":0,"reflected_input":false,"reflected_output":false,"xorout":0,"check_123456789":244,"private_reference_regression":regression,"rows":rows,"exhaustive":exhaustive,"frontiers":frontiers})).unwrap());
}
