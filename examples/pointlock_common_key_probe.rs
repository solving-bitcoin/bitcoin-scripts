//! Common-G sum point locks with native threshold multisig.
//! Public deterministic fixtures, not secret production keys.
use bitcoin::{
    hashes::{sha256, Hash},
    secp256k1::{Message, PublicKey, Secp256k1, SecretKey},
    EcdsaSighashType, ScriptBuf,
};
use bitcoin_lab::{
    signatures::pointlocks,
    support::{
        provenance,
        script::{script, ScriptCompilation},
    },
};
use num_bigint::BigUint;
use serde_json::json;

#[derive(Clone)]
struct Candidate {
    signature: Vec<u8>,
    key: Vec<u8>,
    target: Vec<u8>,
}
fn order() -> BigUint {
    BigUint::parse_bytes(
        b"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        16,
    )
    .unwrap()
}
fn bytes(v: &BigUint) -> [u8; 32] {
    let b = v.to_bytes_be();
    let mut r = [0; 32];
    r[32 - b.len()..].copy_from_slice(&b);
    r
}
fn point(v: &BigUint) -> PublicKey {
    PublicKey::from_secret_key(
        &Secp256k1::new(),
        &SecretKey::from_slice(&bytes(v)).unwrap(),
    )
}
fn hex(v: &[u8]) -> String {
    v.iter().map(|b| format!("{b:02x}")).collect()
}
fn candidates(n: usize) -> Vec<Candidate> {
    let secp = Secp256k1::new();
    let modulus = order();
    let digest = pointlocks::sighash_single_bug_message();
    let c = BigUint::from_bytes_be(&digest);
    let one = SecretKey::from_slice(&bytes(&BigUint::from(1u8))).unwrap();
    let g = PublicKey::from_secret_key(&secp, &one);
    (0..n)
        .map(|i| {
            for counter in 0u32.. {
                let nonce_bytes =
                    sha256::Hash::hash(format!("pointlock-common-key-{i}-{counter}").as_bytes())
                        .to_byte_array();
                let nonce = SecretKey::from_slice(&nonce_bytes).unwrap();
                let sig = pointlocks::sign_with_nonce(digest, one, nonce, EcdsaSighashType::Single)
                    .unwrap();
                // Cheap off-chain length selection: clear the r sign-padding bit, and retain
                // 32-byte r,s. The expected work is approximately two nonce trials.
                if sig.to_vec().len() != 71 || sig.to_vec()[3] != 32 {
                    continue;
                }
                let r = BigUint::from_bytes_be(&sig.signature.serialize_compact()[..32]);
                let scalar = (&modulus
                    - BigUint::from(2u8)
                        * &c
                        * r.modpow(&(&modulus - BigUint::from(2u8)), &modulus)
                        % &modulus)
                    % &modulus;
                let target = point(&scalar);
                let p = target.combine(&g.negate(&secp)).unwrap();
                assert_ne!(p, g);
                secp.verify_ecdsa(&Message::from_digest(digest), &sig.signature, &g)
                    .unwrap();
                secp.verify_ecdsa(&Message::from_digest(digest), &sig.signature, &p)
                    .unwrap();
                return Candidate {
                    signature: sig.to_vec(),
                    key: p.serialize().to_vec(),
                    target: target.serialize().to_vec(),
                };
            }
            unreachable!()
        })
        .collect()
}
fn threshold(c: &[Candidate], t: usize, two_cms: bool) -> ScriptBuf {
    let g = point(&BigUint::from(1u8)).serialize().to_vec();
    script! {
     if two_cms {
      // Preserve a copy of the complete signature list on altstack. Each copy
      // is length-checked before either multisig invocation uses it.
      for i in 0..t {
       { i } OP_PICK OP_SIZE 57 OP_GREATERTHAN OP_VERIFY OP_TOALTSTACK
      }
      {t}
      for row in c { {row.key.clone()} }
      {c.len()} OP_CHECKMULTISIGVERIFY
      0
      for _ in 0..t {OP_FROMALTSTACK}
      {t} {g}
      for _ in 1..t {OP_DUP}
      {t} OP_CHECKMULTISIG
     } else {
      {g}
      for _ in 0..t {
       OP_SWAP OP_SIZE 57 OP_GREATERTHAN OP_VERIFY
       OP_DUP 2 OP_PICK OP_CHECKSIGVERIFY OP_TOALTSTACK
      }
      OP_DROP
      for _ in 0..t {OP_FROMALTSTACK}
      {t}
      for row in c {{row.key.clone()}}
      {c.len()} OP_CHECKMULTISIG
     }
    }
    .compile_with_policy()
}
fn variable_threshold(c: &[Candidate], max_t: usize) -> ScriptBuf {
    let g = point(&BigUint::from(1u8)).serialize().to_vec();
    script! {
        OP_DEPTH OP_1SUB OP_DUP 1 {max_t+1} OP_WITHIN OP_VERIFY OP_TOALTSTACK
        {g}
        for _ in 0..max_t {
            OP_DEPTH 2 OP_GREATERTHAN OP_IF
                OP_SWAP OP_SIZE 57 OP_GREATERTHAN OP_VERIFY
                OP_DUP 2 OP_PICK OP_CHECKSIGVERIFY OP_TOALTSTACK
                1 OP_TOALTSTACK
            OP_ELSE
                0 OP_TOALTSTACK
            OP_ENDIF
        }
        OP_DROP
        for _ in 0..max_t {
            OP_FROMALTSTACK OP_IF OP_FROMALTSTACK OP_ENDIF
        }
        OP_FROMALTSTACK
        for row in c {{row.key.clone()}}
        {c.len()} OP_CHECKMULTISIG
    }
    .compile_with_policy()
}
fn items(c: &[Candidate], selected: &[usize]) -> Vec<Vec<u8>> {
    std::iter::once(vec![])
        .chain(selected.iter().map(|&i| c[i].signature.clone()))
        .collect()
}
fn scriptsig(items: &[Vec<u8>], redeem: &ScriptBuf) -> ScriptBuf {
    let mut b = bitcoin::script::Builder::new();
    for item in items {
        b = if item.is_empty() {
            b.push_int(0)
        } else if item.len() == 1 && (1..=16).contains(&item[0]) {
            b.push_int(i64::from(item[0]))
        } else if item == &[0x81] {
            b.push_int(-1)
        } else {
            b.push_slice(bitcoin::script::PushBytesBuf::try_from(item.clone()).unwrap())
        };
    }
    b.push_slice(bitcoin::script::PushBytesBuf::try_from(redeem.to_bytes()).unwrap())
        .into_script()
}
fn counts(script: &ScriptBuf) -> (usize, usize) {
    let mut ops = 0;
    let mut sigops = 0;
    let mut last = 0;
    for ins in script.instructions() {
        match ins.unwrap() {
            bitcoin::script::Instruction::Op(op) => {
                let code = op.to_u8();
                if code > 0x60 {
                    ops += 1;
                }
                if code == 0xac || code == 0xad {
                    sigops += 1;
                }
                if code == 0xae || code == 0xaf {
                    sigops += if (0x51..=0x60).contains(&last) {
                        (last - 0x50) as usize
                    } else {
                        20
                    };
                }
                last = code;
            }
            bitcoin::script::Instruction::PushBytes(_) => last = 0,
        }
    }
    (ops, sigops)
}
fn main() {
    let c = candidates(15);
    probe_variable(&c);
    let mut cases = Vec::new();
    for two_cms in [false, true] {
        for n in 2..=14 {
            for t in 1..n.min(8) {
                let r = threshold(&c[..n], t, two_cms);
                let (op, sigops) = counts(&r);
                let opening = items(&c[..n], &(0..t).collect::<Vec<_>>());
                let ss = scriptsig(&opening, &r);
                let charged = op + n + if two_cms { t } else { 0 };
                println!("common_g two_cms={two_cms} n={n} t={t} redeem_bytes={} scriptSig_bytes={} static_ops={op} charged_ops={charged} sigops={sigops} hints=0 input_items={} fits_p2sh={} fits_sigops={}",r.len(),ss.len(),t+1,r.len()<=520,sigops<=15);
                if ![(11, 4), (12, 3), (10, 5)].contains(&(n, t)) {
                    continue;
                }
                let mut add = |label: String, data: Vec<Vec<u8>>, expected: bool| {
                    cases.push(json!({"name":format!("common-g-cms-{two_cms}-{n}-{t}-{label}"),"variant":format!("common-g-cms-{two_cms}"),"n":n,"t":t,"script_hex":hex(r.as_bytes()),"items_hex":data.iter().map(|d|hex(d)).collect::<Vec<_>>(),"p2sh_script_sig_hex":hex(scriptsig(&data,&r).as_bytes()),"expected":expected,"expected_policy":expected,"hint_items":0,"compiler_static_ops":op,"compiler_charged_ops":charged}));
                };
                let mut chosen = 0;
                for mask in 0..1usize << n {
                    if mask.count_ones() as usize != t {
                        continue;
                    }
                    let selected: Vec<_> = (0..n).filter(|i| mask & (1 << i) != 0).collect();
                    if chosen < 16 || mask == ((1usize << t) - 1) << (n - t) {
                        add(
                            format!("subset-{selected:?}"),
                            items(&c[..n], &selected),
                            true,
                        );
                    }
                    chosen += 1;
                }
                let mut bad = opening.clone();
                bad[0] = vec![1];
                add("nonempty-dummy".into(), bad, false);
                let mut bad = opening.clone();
                bad[1] = bad[2].clone();
                add("duplicate-signature".into(), bad, false);
                let mut bad = opening.clone();
                bad[1] = c[n].signature.clone();
                add("outside-table".into(), bad, false);
                let mut bad = opening.clone();
                bad[1].truncate(57);
                add("57-byte-signature".into(), bad, false);
                let mut bad = opening.clone();
                *bad[1].last_mut().unwrap() = 1;
                add("wrong-flag".into(), bad, false);
                let mut bad = opening.clone();
                bad.swap(1, 2);
                add("wrong-order".into(), bad, false);
            }
        }
    }
    std::fs::write("research/pointlocks-2026-09-17/common-key-vectors.json",serde_json::to_string_pretty(&json!({"compiler":provenance::compiler().unwrap().commit,"interpreter":provenance::interpreter().unwrap().commit,"candidates":c.iter().map(|row|json!({"key":hex(&row.key),"target":hex(&row.target),"signature":hex(&row.signature)})).collect::<Vec<_>>(),"cases":cases})).unwrap()+"\n").unwrap();
}

fn probe_variable(c: &[Candidate]) {
    let mut cases = Vec::new();
    for n in 5..=13 {
        for max_t in 2..=6.min(n) {
            let r = variable_threshold(&c[..n], max_t);
            let (op, sigops) = counts(&r);
            let charged = op + n;
            let prefix = r.len()
                + if r.len() <= 75 {
                    1
                } else if r.len() <= 255 {
                    2
                } else {
                    3
                }
                + 1;
            println!("common_g_variable n={n} max_t={max_t} redeem_bytes={} scriptSig_base={prefix} signature_increment=72 static_ops={op} charged_ops={charged} sigops={sigops} hints=0 input_items=t+1 fits_p2sh={} fits_sigops={}",r.len(),r.len()<=520,sigops<=15);
            if ![(10, 4), (11, 3), (9, 5)].contains(&(n, max_t)) {
                continue;
            }
            let mut add = |name: String, data: Vec<Vec<u8>>, expected: bool| {
                cases.push(json!({"name":format!("common-g-variable-{n}-{max_t}-{name}"),"variant":"common-g-variable","n":n,"t":max_t,"script_hex":hex(r.as_bytes()),"items_hex":data.iter().map(|d|hex(d)).collect::<Vec<_>>(),"p2sh_script_sig_hex":hex(scriptsig(&data,&r).as_bytes()),"expected":expected,"expected_policy":expected,"hint_items":0,"compiler_static_ops":op,"compiler_charged_ops":charged}));
            };
            for t in 1..=max_t {
                let first: Vec<_> = (0..t).collect();
                let last: Vec<_> = (n - t..n).collect();
                add(format!("first-{t}"), items(c, &first), true);
                add(format!("last-{t}"), items(c, &last), true);
                if t >= 2 {
                    let mut bad = items(c, &first);
                    bad[1] = bad[2].clone();
                    add(format!("duplicate-{t}"), bad, false);
                    let mut bad = items(c, &first);
                    bad.swap(1, 2);
                    add(format!("unordered-{t}"), bad, false);
                }
                let mut bad = items(c, &first);
                bad[0] = vec![1];
                add(format!("nonempty-dummy-{t}"), bad, false);
                let mut bad = items(c, &first);
                bad[1] = c[n].signature.clone();
                add(format!("outside-table-{t}"), bad, false);
            }
            add("empty".into(), items(c, &[]), false);
            add(
                "too-many".into(),
                items(c, &(0..max_t + 1).collect::<Vec<_>>()),
                false,
            );
        }
    }
    std::fs::write(
        "research/pointlocks-2026-09-17/common-key-variable-vectors.json",
        serde_json::to_string_pretty(
            &json!({"compiler":provenance::compiler().unwrap().commit,"cases":cases}),
        )
        .unwrap()
            + "\n",
    )
    .unwrap();
}
