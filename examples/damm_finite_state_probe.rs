//! Research-only Damm scheduling comparison, prior to public promotion.
use bitcoin::{
    consensus::encode::serialize,
    hashes::{sha256, Hash},
    script::Instruction,
    Witness,
};
use bitcoin_lab::{
    arithmetic::{scriptint::mul_by_constant, u4::stack::u4_drop},
    support::{
        provenance,
        script::*,
        tapscript::{execute_tapscript, TapscriptOutcome, TapscriptProfile},
    },
};
use bitcoin_scriptexec::ExecError;
use serde_json::{json, Value};
// Fixed numeric table transcribed from the pinned upstream implementation.
// Its preserved MIT license and exact original source are in research/reference.
const Q: [[u8; 10]; 10] = [
    [0, 3, 1, 7, 5, 9, 8, 6, 4, 2],
    [7, 0, 9, 2, 1, 5, 4, 8, 6, 3],
    [4, 2, 0, 6, 8, 7, 1, 3, 5, 9],
    [1, 7, 5, 0, 9, 8, 3, 4, 2, 6],
    [6, 1, 2, 3, 0, 4, 5, 9, 7, 8],
    [3, 6, 7, 4, 2, 0, 9, 5, 8, 1],
    [5, 8, 6, 9, 7, 2, 0, 1, 3, 4],
    [8, 9, 4, 5, 3, 6, 2, 0, 1, 7],
    [9, 4, 3, 8, 6, 1, 7, 2, 0, 5],
    [2, 5, 8, 1, 4, 3, 6, 7, 9, 0],
];
fn guard() -> Script {
    script! {OP_DUP 0 10 OP_WITHIN OP_VERIFY}
}
fn table() -> Script {
    script! {for a in (0..10).rev(){for b in (0..10).rev(){{Q[a][b]}}}}
}
fn map(lo: u32, hi: u32) -> Script {
    if hi - lo == 1 {
        return script! {OP_DROP{Q[lo as usize/10][lo as usize%10]}};
    }
    let mid = (lo + hi) / 2;
    script! {OP_DUP{mid}OP_LESSTHAN OP_IF{map(lo,mid)}OP_ELSE{map(mid,hi)}OP_ENDIF}
}
fn row_map(lo: u32, hi: u32) -> Script {
    if hi - lo == 1 {
        return script! {OP_DROP for d in (0..10).rev(){{Q[lo as usize][d]}}};
    }
    let mid = (lo + hi) / 2;
    script! {OP_DUP{mid}OP_LESSTHAN OP_IF{row_map(lo,mid)}OP_ELSE{row_map(mid,hi)}OP_ENDIF}
}
fn row_table(n: u32) -> Script {
    assert!(n <= 1000);
    if n == 0 {
        return script! {0};
    }
    script! {
        // Initial state zero selects the first row directly. Later rows are
        // runtime-selected; their ephemeral table contains ten live entries.
        {n-1}OP_ROLL{guard()}OP_TOALTSTACK
        for d in (0..10).rev(){{Q[0][d]}}
        OP_FROMALTSTACK OP_PICK
        OP_TOALTSTACK{u4_drop(10)}OP_FROMALTSTACK
        for i in 1..n {
            {n-i}OP_ROLL{guard()}OP_TOALTSTACK
            {row_map(0,10)} OP_FROMALTSTACK OP_PICK
            OP_TOALTSTACK{u4_drop(10)}OP_FROMALTSTACK
        }
    }
}
fn resident(n: u32) -> Script {
    assert!(n <= 1000);
    if n == 0 {
        return script! {0};
    }
    script! {{table()}0 for i in 0..n{{100+n-i}OP_ROLL{guard()}OP_SWAP{mul_by_constant(10)}OP_ADD OP_PICK}OP_TOALTSTACK{u4_drop(100)}OP_FROMALTSTACK}
}
fn dispatch(n: u32) -> Script {
    assert!(n <= 1000);
    if n == 0 {
        return script! {0};
    }
    script! {{n-1}OP_ROLL{guard()}{map(0,10)}for i in 1..n{{n-i}OP_ROLL{guard()}OP_SWAP{mul_by_constant(10)}OP_ADD{map(0,100)}}}
}
fn warmup(n: u32) -> Script {
    assert!(n <= 1000);
    if n <= 1 {
        return dispatch(n);
    }
    script! {{n-1}OP_ROLL{guard()}{map(0,10)}OP_TOALTSTACK{table()}OP_FROMALTSTACK for i in 1..n{{100+n-i}OP_ROLL{guard()}OP_SWAP{mul_by_constant(10)}OP_ADD OP_PICK}OP_TOALTSTACK{u4_drop(100)}OP_FROMALTSTACK}
}
fn num(x: i64) -> Vec<u8> {
    let mut b = [0; 8];
    let n = bitcoin::script::write_scriptint(&mut b, x);
    b[..n].to_vec()
}
fn run(s: bitcoin::ScriptBuf, w: Vec<Vec<u8>>) -> bitcoin_lab::support::execution::ExecuteInfo {
    match execute_tapscript(s, w, TapscriptProfile::Consensus).outcome {
        TapscriptOutcome::Executed(r) => r,
        o => panic!("unexpected outcome: {o:?}"),
    }
}
fn oracle(d: &[u8]) -> u8 {
    d.iter().fold(0, |s, &x| Q[s as usize][x as usize])
}
fn leaf(f: Script, out: u8) -> Script {
    script! {{f}{out}OP_EQUALVERIFY OP_TRUE}
}
fn row(name: &str, g: fn(u32) -> Script, n: u32) -> Value {
    let d: Vec<_> = (0..n).map(|i| ((7 * i + 3) % 10) as u8).collect();
    let w: Vec<_> = d.iter().map(|&x| num(x.into())).collect();
    let f = g(n);
    let raw = f.len();
    let s = f.clone().compile_with_policy();
    let l = leaf(f, oracle(&d));
    let lraw = l.len();
    let ls = l.compile_with_policy();
    let r = run(ls.clone(), w.clone());
    json!({"algorithm":name,"n":n,"digit_pattern":"(7*i+3)%10, left-to-right","fragment_bytes":s.len(),"fragment_raw_bytes":raw,"fragment_options":if raw<=MAX_OPTIMIZER_INPUT_BYTES{"ALL"}else{"NONE"},"fragment_sha256":sha256::Hash::hash(s.as_bytes()).to_string(),"leaf_bytes":ls.len(),"leaf_raw_bytes":lraw,"leaf_options":if lraw<=MAX_OPTIMIZER_INPUT_BYTES{"ALL"}else{"NONE"},"leaf_sha256":sha256::Hash::hash(ls.as_bytes()).to_string(),"witness_bytes":serialize(&Witness::from_slice(&w)).len(),"data_items":n,"hint_items":0,"max_stack_items":r.stats.max_nb_stack_items,"success":r.success,"error":r.error.map(|e|format!("{e:?}")),"static_non_push_opcodes":s.instructions().filter(|i|matches!(i,Ok(Instruction::Op(op))if op.to_u8()>0x60)).count(),"executed_opcodes":null,"expected_output":oracle(&d)})
}
fn main() {
    let source_revision = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "working-tree".into());
    let families: [(&str, fn(u32) -> Script); 4] = [
        ("resident", resident),
        ("dispatch", dispatch),
        ("warmup", warmup),
        ("row-table", row_table),
    ];
    // Table properties establish local single-digit and adjacent unequal-swap
    // detection for this table; no cryptographic authentication follows.
    for a in 0..10 {
        assert_eq!(Q[a][a], 0);
        let mut row = Q[a];
        row.sort();
        assert_eq!(row, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let mut col = std::array::from_fn::<_, 10, _>(|b| Q[b][a]);
        col.sort();
        assert_eq!(col, row);
    }
    for c in 0..10 {
        for x in 0..10 {
            for y in 0..10 {
                assert_eq!(Q[Q[c][x] as usize][y] == Q[Q[c][y] as usize][x], x == y);
            }
        }
    }
    let mut checks = 0;
    for (name, g) in families {
        // Every decimal vector through length three, plus asymmetric long inputs.
        for n in 0..=3 {
            let leaves: Vec<_> = (0..10)
                .map(|out| leaf(g(n), out).compile_with_policy())
                .collect();
            for v in 0..10u32.pow(n) {
                let d: Vec<_> = (0..n)
                    .map(|i| ((v / 10u32.pow(n - i - 1)) % 10) as u8)
                    .collect();
                let w = d.iter().map(|&x| num(x.into())).collect();
                let r = run(leaves[oracle(&d) as usize].clone(), w);
                assert_eq!(r.error, None, "{name} {d:?}");
                assert!(r.success);
                checks += 1;
            }
        }
        for n in [4, 32, 128] {
            let d: Vec<_> = (0..n).map(|i| ((i * 7 + 3) % 10) as u8).collect();
            let r = run(
                leaf(g(n), oracle(&d)).compile_with_policy(),
                d.iter().map(|&x| num(x.into())).collect(),
            );
            assert_eq!(r.error, None, "{name}");
            assert!(r.success);
        }
        let s = script! {{g(4)}OP_DROP OP_TRUE}.compile_with_policy();
        let good = vec![num(0); 4];
        let r = run(s.clone(), good.clone());
        assert!(r.success);
        assert_eq!(r.error, None);
        for p in 0..4 {
            for (bad, e) in [
                (num(-1), ExecError::Verify),
                (num(10), ExecError::Verify),
                (vec![0; 5], ExecError::ScriptIntNumericOverflow),
                (vec![0; 521], ExecError::PushSize),
            ] {
                let mut w = good.clone();
                w[p] = bad;
                assert_eq!(run(s.clone(), w).error, Some(e), "{name} position{p}");
            }
        }
        for pos in 0..4 {
            for (alias, value) in [(vec![0], 0), (vec![0x80], 0), (vec![1, 0], 1)] {
                let mut digits = vec![0; 4];
                digits[pos] = value;
                let mut w: Vec<_> = digits.iter().map(|&d| num(d.into())).collect();
                w[pos] = alias;
                let r = run(leaf(g(4), oracle(&digits)).compile_with_policy(), w);
                assert_eq!(r.error, None, "{name}: numeric alias at {pos}");
                assert!(r.success);
            }
        }
        // Same typed assertion catches the actual compiled range-guard bypass.
        // A zero caller item keeps out-of-table PICK observable yet available
        // in the row-table mutant, including at the final digit position.
        let original = script! {{g(4)}OP_2DROP OP_TRUE}.compile_with_policy();
        let pattern = guard().compile_with_policy().to_bytes();
        let mut bytes = original.to_bytes();
        let mut hits = 0;
        while let Some(i) = bytes.windows(pattern.len()).position(|w| w == pattern) {
            bytes.drain(i..i + pattern.len());
            hits += 1;
        }
        assert_eq!(hits, 4, "{name}: all digit guards must be mutated");
        let mutant = bitcoin::ScriptBuf::from_bytes(bytes);
        let control = vec![num(0); 5];
        for s in [original.clone(), mutant.clone()] {
            let r = run(s, control.clone());
            assert_eq!(r.error, None);
            assert!(r.success);
        }
        let rejects = |r: &bitcoin_lab::support::execution::ExecuteInfo| {
            assert_eq!(r.error, Some(ExecError::Verify))
        };
        for pos in 1..=4 {
            let mut w = control.clone();
            w[pos] = num(10);
            rejects(&run(original.clone(), w.clone()));
            let r = run(mutant.clone(), w);
            assert_eq!(r.error, None);
            assert!(r.success);
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| rejects(&r))).is_err()
            );
        }
    }
    let mut rows = Vec::new();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let source_sha256: serde_json::Map<_, _> = [
        "examples/damm_finite_state_probe.rs",
        "research/damm-finite-state/verify_reference.py",
        "Cargo.lock",
        "src/support/script.rs",
        "src/support/execution.rs",
        "src/support/tapscript.rs",
        "src/support/provenance.rs",
        "src/arithmetic/scriptint/mod.rs",
        "src/arithmetic/u4/stack.rs",
        "research/damm-finite-state/reference/DammAlgorithm.cs",
        "research/damm-finite-state/reference/DammQuasigroupTable.cs",
        "research/damm-finite-state/reference/LICENSE.txt",
    ]
    .into_iter()
    .map(|p| {
        (
            p.to_owned(),
            json!(sha256::Hash::hash(&std::fs::read(root.join(p)).unwrap()).to_string()),
        )
    })
    .collect();
    for (name, g) in families {
        for n in [
            0, 1, 2, 3, 4, 8, 16, 32, 128, 896, 897, 898, 990, 991, 997, 998,
        ] {
            rows.push(row(name, g, n));
        }
    }
    println!("{}",serde_json::to_string_pretty(&json!({"stage":"initial research prototype; no public source change","source_revision":source_revision,"source_sha256":source_sha256,"compiler_source":provenance::compiler().unwrap().source,"interpreter_source":provenance::interpreter().unwrap().source,"evidence":"locally-reproduced","execution":"unclassified","vector_checks":checks,"source_base":"bf9ee0bb34987a9130ad9dc13a06e18fef137296","reference_revision":"734afa2d3596862ef4c3bb3ec404b512b96b8965","profile":"Consensus tapscript, numeric minimality off, MINIMALIF and stack checks on, OP_CAT off, synthetic empty transaction/data-only witness, no signatures","boundary":"fragment includes table setup/cleanup, digit guards, forward routing and final state; leaf checks exact output then TRUE; all n ordinary data items present at entry, zero hints; witness excludes script/control block/annex/transaction","rows":rows})).unwrap());
}
