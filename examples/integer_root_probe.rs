//! Private initial experiment: no production API has been changed.
use bitcoin::{
    consensus::encode::serialize,
    hashes::{sha256, Hash},
    script::Instruction,
    ScriptBuf, Witness,
};
use bitcoin_lab::{
    arithmetic::scriptint::mul_by_constant,
    support::{
        execution::ExecuteInfo,
        provenance,
        script::*,
        tapscript::{execute_tapscript, TapscriptOutcome, TapscriptProfile},
    },
};
use bitcoin_scriptexec::ExecError;
use serde_json::{json, Value};

fn max(bits: u32) -> u32 {
    assert!((1..=31).contains(&bits));
    (1u32 << bits) - 1
}
fn guard(bits: u32) -> Script {
    script! {OP_DUP 0 OP_GREATERTHANOREQUAL OP_VERIFY OP_DUP {max(bits)} OP_LESSTHANOREQUAL OP_VERIFY}
}
fn restoring(bits: u32) -> Script {
    let root_bits = (bits + 1) / 2;
    script! {
        {guard(bits)} 0
        for bit in (0..root_bits).rev() {
            // Main: residual, root. Candidate square difference fits ScriptNum.
            OP_DUP {mul_by_constant(2*(1u32<<bit))} {(1u32<<bit).pow(2)} OP_ADD
            2 OP_PICK OP_OVER OP_GREATERTHANOREQUAL
            OP_IF
                OP_ROT OP_SWAP OP_SUB OP_SWAP {1u32<<bit} OP_ADD
            OP_ELSE OP_DROP OP_ENDIF
        }
        OP_NIP
    }
}
fn host_root(x: u32) -> u32 {
    let (mut lo, mut hi) = (0u32, 65536u32);
    while lo + 1 < hi {
        let m = (lo + hi) / 2;
        if u64::from(m) * u64::from(m) <= u64::from(x) {
            lo = m
        } else {
            hi = m
        }
    }
    lo
}
fn threshold_map(lo: u32, hi: u32) -> Script {
    if lo == hi {
        return script! {OP_DROP{lo}};
    }
    let mid = (lo + hi + 1) / 2;
    script! {OP_DUP {mid*mid} OP_LESSTHAN OP_IF {threshold_map(lo,mid-1)} OP_ELSE {threshold_map(mid,hi)} OP_ENDIF}
}
fn thresholds(bits: u32) -> Script {
    script! {{guard(bits)}{threshold_map(0,host_root(max(bits)))}}
}
fn num(x: i64) -> Vec<u8> {
    let mut b = [0; 8];
    let n = bitcoin::script::write_scriptint(&mut b, x);
    b[..n].to_vec()
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
fn output(r: &ExecuteInfo, q: u32) {
    assert!(r.stack_limit_enforced);
    assert_eq!(r.error, None, "{r}");
    assert_eq!(r.final_stack.len(), 1);
    assert_eq!(r.final_stack.get(0), num(q.into()));
}
fn clean(r: &ExecuteInfo) {
    output(r, 1);
    assert!(r.success)
}
fn rejects(r: &ExecuteInfo, e: ExecError) {
    assert!(r.stack_limit_enforced);
    assert_eq!(r.error, Some(e), "{r}");
    assert!(!r.success)
}
fn caught(r: &ExecuteInfo, e: ExecError) {
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| rejects(r, e))).is_err())
}
fn artifact(g: Script, w: &[Vec<u8>]) -> Value {
    let raw = g.len();
    let s = g.compile_with_policy();
    let r = run(s.clone(), w.to_vec());
    json!({"raw_bytes":raw,"compile_options":if raw<=32768{"ALL"}else{"NONE"},"script_bytes":s.len(),"sha256":sha(s.as_bytes()),"static_non_push_opcodes":s.instructions().filter(|i|matches!(i,Ok(Instruction::Op(op))if op.to_u8()>0x60)).count(),"executed_opcodes":null,"validation_weight_charged":r.stats.start_validation_weight-r.stats.validation_weight,"error":r.error.as_ref().map(|e|format!("{e:?}")),"clean_success":r.success,"max_stack_items":r.stats.max_nb_stack_items,"output_items":r.final_stack.len(),"output_hex":(0..r.final_stack.len()).map(|i|r.final_stack.get(i).iter().map(|b|format!("{b:02x}")).collect::<String>()).collect::<Vec<_>>()})
}
fn checks(g: fn(u32) -> Script) -> (String, Vec<Value>) {
    let s = g(16).compile_with_policy();
    let mut outputs = Vec::new();
    for x in 0..65536 {
        let q = host_root(x);
        output(&run(s.clone(), vec![num(x.into())]), q);
        outputs.extend(q.to_le_bytes())
    }
    for bits in 1..=31 {
        for x in [0, 1, max(bits) / 2, max(bits)] {
            output(
                &run(g(bits).compile_with_policy(), vec![num(x.into())]),
                host_root(x),
            )
        }
    }
    let control = script! {{g(16)}255 OP_EQUALVERIFY OP_TRUE}.compile_with_policy();
    clean(&run(control, vec![num(65535)]));
    let original = script! {{g(16)}OP_DROP OP_TRUE}.compile_with_policy();
    clean(&run(original.clone(), vec![num(12345)]));
    for x in [-1, 65536, 2147483647] {
        rejects(&run(original.clone(), vec![num(x)]), ExecError::Verify)
    }
    for size in [5, 80, 81, 520, 521] {
        rejects(
            &run(original.clone(), vec![vec![0; size]]),
            if size == 521 {
                ExecError::PushSize
            } else {
                ExecError::ScriptIntNumericOverflow
            },
        )
    }
    rejects(
        &run(original.clone(), vec![]),
        ExecError::InvalidStackOperation,
    );
    for (b, x) in [
        (vec![0], 0),
        (vec![0x80], 0),
        (vec![1, 0], 1),
        (vec![1, 0, 0, 0], 1),
    ] {
        output(&run(s.clone(), vec![b]), host_root(x))
    }
    // Actual compiled guard bypasses retain the same exact leaf/cleanup/control.
    let pat = guard(16).compile_with_policy().to_bytes();
    for (good, bad, q) in [(65535, 65536, 255), (0, -1, 0)] {
        let original = script! {{g(16)}{q}OP_EQUALVERIFY OP_TRUE}.compile_with_policy();
        let mut bytes = original.to_bytes();
        let hits = bytes.windows(pat.len()).filter(|w| *w == pat).count();
        assert_eq!(hits, 1);
        let at = bytes.windows(pat.len()).position(|w| w == pat).unwrap();
        bytes.drain(at..at + pat.len());
        let mutant = ScriptBuf::from_bytes(bytes);
        clean(&run(original.clone(), vec![num(good)]));
        clean(&run(mutant.clone(), vec![num(good)]));
        rejects(&run(original, vec![num(bad)]), ExecError::Verify);
        let r = run(mutant, vec![num(bad)]);
        clean(&r);
        caught(&r, ExecError::Verify);
    }
    let original = script! {{g(16)}12 OP_EQUALVERIFY OP_TRUE}.compile_with_policy();
    let pat = script! {12 OP_EQUALVERIFY}.compile_with_policy().to_bytes();
    let mut bytes = original.to_bytes();
    let at = bytes.windows(pat.len()).position(|w| w == pat).unwrap();
    bytes.splice(at..at + pat.len(), [0x75]);
    let mutant = ScriptBuf::from_bytes(bytes);
    clean(&run(original.clone(), vec![num(144)]));
    clean(&run(mutant.clone(), vec![num(144)]));
    rejects(&run(original, vec![num(169)]), ExecError::EqualVerify);
    let r = run(mutant, vec![num(169)]);
    clean(&r);
    caught(&r, ExecError::EqualVerify);
    let peak = run(s.clone(), vec![num(65535)]).stats.max_nb_stack_items;
    let mut frontiers = Vec::new();
    for a in [0, 3] {
        let count = 1000 - peak;
        let main = vec![vec![0x92]; count - a];
        let alt = vec![vec![0x83]; a];
        let mut w = main.clone();
        w.extend(alt.clone());
        w.push(num(65535));
        let wrapper =
            script! {for _ in 0..a {OP_SWAP OP_TOALTSTACK}{g(16)}for _ in 0..a{OP_FROMALTSTACK}};
        let r = run(wrapper.clone().compile_with_policy(), w.clone());
        assert_eq!(r.error, None);
        assert_eq!(r.stats.max_nb_stack_items, 1000);
        let mut expected = main;
        expected.push(num(255));
        expected.extend(alt);
        assert_eq!(r.final_stack.len(), expected.len());
        for (i, x) in expected.iter().enumerate() {
            assert_eq!(&r.final_stack.get(i), x)
        }
        frontiers.push(json!({"caller_main_items":count-a,"caller_alt_items":a,"data_items":w.len(),"hint_items":0,"witness_bytes":encoded(&w).len(),"witness_sha256":sha(&encoded(&w)),"artifact":artifact(wrapper.clone(),&w)}));
        w.insert(0, vec![0x92]);
        rejects(&run(wrapper.compile_with_policy(), w), ExecError::StackSize);
    }
    (sha(&outputs), frontiers)
}
fn main() {
    let rev = std::env::args().nth(1).expect("source revision required");
    assert_eq!(rev.len(), 40);
    let mut rows = Vec::new();
    let mut contracts = Vec::new();
    for (name, g) in [
        ("restoring", restoring as fn(u32) -> Script),
        ("thresholds", thresholds),
    ] {
        let (digest, frontiers) = checks(g);
        contracts.push(json!({"algorithm":name,"exhaustive_16bit_inputs":65536,"root_u32le_sha256":digest,"frontiers":frontiers}));
        for bits in [8, 16, 24, 31] {
            for x in [
                0,
                1,
                2,
                3,
                max(bits) / 2,
                0x13579b & max(bits),
                max(bits) - 1,
                max(bits),
            ] {
                let q = host_root(x);
                let w = vec![num(x.into())];
                let f = g(bits);
                rows.push(json!({"algorithm":name,"bits":bits,"input":x,"expected_root":q,"data_items":1,"hint_items":0,"hint_bytes":0,"witness_bytes":encoded(&w).len(),"witness_sha256":sha(&encoded(&w)),"fragment":artifact(f.clone(),&w),"leaf":artifact(script!{{f}{q}OP_EQUALVERIFY OP_TRUE},&w)}));
            }
        }
    }
    // Every distinct endpoint around every representable 31-bit square.
    let mut cases = std::collections::BTreeSet::new();
    for q in 0..=host_root(max(31)) {
        let sq = q * q;
        cases.insert(sq);
        if sq > 0 {
            cases.insert(sq - 1);
        }
        let end = (u64::from(q) + 1).pow(2) - 1;
        cases.insert(end.min(u64::from(max(31))) as u32);
    }
    let s = restoring(31).compile_with_policy();
    let mut digest = Vec::new();
    for &x in &cases {
        let q = host_root(x);
        output(&run(s.clone(), vec![num(x.into())]), q);
        digest.extend(x.to_le_bytes());
        digest.extend(q.to_le_bytes());
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut bindings = serde_json::Map::new();
    for p in [
        "examples/integer_root_probe.rs",
        "research/integer-root-bounds/verify_probe.py",
        "Cargo.lock",
        "src/arithmetic/scriptint/mod.rs",
        "src/support/script.rs",
        "src/support/execution.rs",
        "src/support/tapscript.rs",
        "src/support/provenance.rs",
    ] {
        bindings.insert(p.into(), json!(sha(&std::fs::read(root.join(p)).unwrap())));
    }
    println!("{}",serde_json::to_string_pretty(&json!({"source_revision":rev,"source_sha256":bindings,"compiler_source":provenance::compiler().unwrap().source,"interpreter_source":provenance::interpreter().unwrap().source,"evidence":"locally-reproduced","execution":"unclassified","profile":{"context":"Tapscript","require_minimal":false,"verify_minimal_if":true,"verify_cltv":true,"verify_csv":true,"enforce_stack_limit":true,"experimental_op_cat":false,"transaction":"synthetic empty transaction, data-only budget, no signatures"},"boundary":"Fragment includes hostile numeric range checks, all root calculation and residual cleanup, preserving caller stacks; one ordinary data item, zero hints, all data at entry. Excludes witness pushes and terminal predicate. Leaf binds exact canonical root then TRUE. Witness excludes script/control block/annex/transaction.","counter_note":"Dynamic executed counts unavailable; static non-push counts separate. Zero charged signature weight is not a complete transaction budget.","independent_oracle":"CPython v3.14.7 823f0323ee6ec1402088b73bce1a38473cac36dc math.isqrt, actual runtime recorded by Python verifier","algorithm_context":"Linux v6.18 7d0a66e4bb9081d75c82ec4957c50034cb0ea449 int_sqrt is established shift/subtract context, not ported code or a new root algorithm","contracts":contracts,"restoring31_boundary_cases":cases.len(),"restoring31_input_root_u32le_sha256":sha(&digest),"rows":rows})).unwrap());
}
