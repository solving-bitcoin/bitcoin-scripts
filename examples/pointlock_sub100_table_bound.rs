//! Lower bounds and bare-legacy sizing for explicit independent point tables.
//! This does not prove a lower bound for arbitrary Bitcoin Script constructions.
#[allow(dead_code)]
#[path = "pointlock_sum_lookup_probe.rs"]
mod layout;
use bitcoin::{
    hashes::{hash160, Hash},
    script::{Builder, PushBytesBuf},
    ScriptBuf,
};
use bitcoin_lab::support::{
    provenance,
    script::{script, ScriptCompilation},
};
fn entropy(p: f64) -> f64 {
    -p * p.log2() - (1. - p) * (1. - p).log2()
}
fn minimum(a: f64, b: f64) -> (f64, f64) {
    let (mut l, mut r) = (0.000000001, 0.999999999);
    for _ in 0..120 {
        let x = l + (r - l) / 3.;
        let y = r - (r - l) / 3.;
        if (a + b * x) / entropy(x) < (a + b * y) / entropy(y) {
            r = y
        } else {
            l = x
        }
    }
    let p = (l + r) / 2.;
    (p, (a + b * p) / entropy(p))
}
fn log_choose(n: usize, t: usize) -> f64 {
    (0..t)
        .map(|i| ((n - i) as f64).log2() - ((i + 1) as f64).log2())
        .sum()
}
fn bare(c: &[layout::Candidate], t: usize, g: &[u8]) -> ScriptBuf {
    script! {
     for _ in 0..3*t {OP_TOALTSTACK}
     {g.to_vec()}
     for row in c {{hash160::Hash::hash(&row.key).to_byte_array().to_vec()}}
     for j in 0..t {
      OP_FROMALTSTACK OP_SIZE 57 OP_GREATERTHAN OP_VERIFY
      OP_FROMALTSTACK OP_FROMALTSTACK
      OP_DUP 2 {c.len()-j+2} OP_WITHIN OP_VERIFY
      OP_ROLL OP_OVER OP_HASH160 OP_EQUALVERIFY
      OP_OVER {c.len()-j+2} OP_PICK OP_CHECKSIGVERIFY OP_CHECKSIGVERIFY
     }
     // Bare legacy consensus does not require CLEANSTACK. Omitting unused-table
     // cleanup favors this sizing experiment; this output is not standard policy.
     OP_TRUE
    }
    .compile_with_policy()
}
fn scriptsig(c: &[layout::Candidate], t: usize) -> ScriptBuf {
    let mut b = Builder::new();
    for (j, row) in c.iter().take(t).enumerate() {
        b = b
            .push_slice(PushBytesBuf::try_from(row.signature.clone()).unwrap())
            .push_slice(PushBytesBuf::try_from(row.key.clone()).unwrap())
            .push_int((c.len() + 1 - j) as i64);
    }
    b.into_script()
}
fn compact_len(v: usize) -> usize {
    if v < 253 {
        1
    } else if v <= 65535 {
        3
    } else {
        5
    }
}
fn main() {
    println!("compiler={}", provenance::compiler().unwrap().commit);
    for (a, b, label) in [
        (21., 106., "hashed_key_actual71"),
        (21., 93., "hashed_key_minimum58"),
        (34., 72., "embedded_key_actual71"),
        (34., 59., "embedded_key_minimum58"),
    ] {
        let (p, rate) = minimum(a, b);
        println!("bound {label} optimal_density={p:.9} minimum_vbytes_per_bit={rate:.9} minimum_2048bit_vbytes={:.6}",2048.*rate);
    }
    let (all, g) = layout::candidates(400);
    let mut best = (f64::INFINITY, 0, 0, 0, 0);
    for n in [8, 12, 16, 20, 24, 32, 48, 64, 96, 128, 256, 400] {
        for t in 1..=7.min(n - 1) {
            let r = bare(&all[..n], t, &g);
            let ss = scriptsig(&all[..n], t);
            let ops = r
                .instructions()
                .filter(|v| matches!(v,Ok(bitcoin::script::Instruction::Op(op))if op.to_u8()>0x60))
                .count();
            let bits = log_choose(n, t);
            let pair = 8 + compact_len(r.len()) + r.len() + 40 + compact_len(ss.len()) + ss.len();
            let rate = pair as f64 / bits;
            if r.len() <= 10000 && ops <= 201 && rate < best.0 {
                best = (rate, n, t, r.len(), ss.len());
            }
            println!("bare n={n} t={t} script={} scriptSig={} static_ops={ops} sigops={} bits={bits:.6} incremental_creation_and_spending_bytes={pair} bytes_per_bit={rate:.6} size_and_op_limits={}",r.len(),ss.len(),2*t,r.len()<=10000&&ops<=201);
        }
    }
    println!("best_sampled_bare bytes_per_bit={:.6} n={} t={} script={} scriptSig={} asymptotic_2048bit_bytes={:.3}",best.0,best.1,best.2,best.3,best.4,best.0*2048.);
}
