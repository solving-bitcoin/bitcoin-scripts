//! Reduced-work native P2WSH fixture. cap=59, not the proposed production cap=53.
//! All secrets are deterministic public test fixtures and are unsuitable for funds.
#[allow(dead_code)]
#[path = "pointlock_windowed_size_probe.rs"]
mod layout;
use bitcoin::{
    absolute,
    consensus::serialize,
    hashes::{hash160, sha256, Hash},
    script::Builder,
    secp256k1::{Keypair, Message, PublicKey, Secp256k1, SecretKey},
    sighash::{Prevouts, SighashCache},
    transaction, Amount, EcdsaSighashType, OutPoint, ScriptBuf, Sequence, TapSighashType,
    Transaction, TxIn, TxOut, Witness,
};
use bitcoin_lab::{signatures::pointlocks, support::provenance};
use bitcoin_scriptexec::{Exec, ExecCtx, Options, TxTemplate};
use num_bigint::BigUint;
use serde_json::{json, Value};
use std::str::FromStr;
const CAP: usize = 59;
fn choose(n: usize, t: usize) -> u64 {
    let t = t.min(n - t);
    (0..t).fold(1u64, |v, j| v * (n - j) as u64 / (j + 1) as u64)
}
fn unrank(mut rank: u64, n: usize, t: usize) -> Vec<usize> {
    let mut out = vec![];
    let mut low = 0;
    for j in 0..t {
        for candidate in low..n {
            let count = choose(n - candidate - 1, t - j - 1);
            if rank >= count {
                rank -= count;
            } else {
                out.push(candidate);
                low = candidate + 1;
                break;
            }
        }
    }
    assert_eq!(rank, 0);
    assert_eq!(out.len(), t);
    out
}
fn rank(selection: &[usize], n: usize) -> u64 {
    let mut out = 0;
    let mut low = 0;
    for (j, &v) in selection.iter().enumerate() {
        for candidate in low..v {
            out += choose(n - candidate - 1, selection.len() - j - 1);
        }
        low = v + 1;
    }
    out
}
fn hex(v: &[u8]) -> String {
    v.iter().map(|b| format!("{b:02x}")).collect()
}
fn scalar(v: &BigUint) -> SecretKey {
    let b = v.to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - b.len()..].copy_from_slice(&b);
    SecretKey::from_slice(&out).unwrap()
}
fn one() -> SecretKey {
    scalar(&BigUint::from(1u8))
}
fn p2tr() -> ScriptBuf {
    Builder::new()
        .push_int(1)
        .push_slice(
            PublicKey::from_secret_key(&Secp256k1::new(), &one())
                .x_only_public_key()
                .0
                .serialize(),
        )
        .into_script()
}
fn input(previous_output: OutPoint) -> TxIn {
    TxIn {
        previous_output,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::MAX,
        witness: Witness::new(),
    }
}
fn sign_helper(tx: &mut Transaction, prevouts: &[TxOut]) {
    let hash = SighashCache::new(&*tx)
        .taproot_key_spend_signature_hash(0, &Prevouts::All(prevouts), TapSighashType::Default)
        .unwrap();
    let secp = Secp256k1::new();
    let kp = Keypair::from_secret_key(&secp, &one());
    tx.input[0].witness = Witness::from_slice(&[secp
        .sign_schnorr_no_aux_rand(&Message::from_digest(hash.to_byte_array()), &kp)
        .as_ref()]);
}
fn info(tx: &Transaction) -> Value {
    json!({"hex":hex(&serialize(tx)),"txid":tx.compute_txid().to_string(),"weight":tx.weight().to_wu(),"vbytes":tx.vsize()})
}
fn nonce_output(nonce: u64) -> TxOut {
    TxOut {
        value: Amount::ZERO,
        script_pubkey: Builder::new()
            .push_opcode(bitcoin::opcodes::all::OP_RETURN)
            .push_slice(nonce.to_le_bytes())
            .into_script(),
    }
}
fn digest(tx: &Transaction, i: usize, script: &ScriptBuf, amount: Amount) -> [u8; 32] {
    SighashCache::new(tx)
        .p2wsh_signature_hash(i, script, amount, EcdsaSighashType::SinglePlusAnyoneCanPay)
        .unwrap()
        .to_byte_array()
}
struct Pool {
    b: BigUint,
    offsets: Vec<BigUint>,
    secrets: Vec<SecretKey>,
    keys: Vec<Vec<u8>>,
    script: ScriptBuf,
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    let arg = |name: &str| args[args.iter().position(|x| x == name).unwrap() + 1].clone();
    let profile = args
        .iter()
        .position(|s| s == "--profile")
        .map(|j| args[j + 1].as_str())
        .unwrap_or("two-pool");
    assert!(matches!(profile, "two-pool" | "full256" | "batch256"));
    let batch = profile == "batch256";
    let full = profile != "two-pool";
    let (pool_count, nkeys, threshold) = match profile {
        "batch256" => (35, 76, 24),
        "full256" => (52, 64, 11),
        _ => (2, 8, 3),
    };
    let blocks = if batch { 4 } else { 1 };
    let keys_per_block = if batch { 19 } else { nkeys };
    let selected_per_block = if batch { 6 } else { threshold };
    let order = BigUint::parse_bytes(
        b"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        16,
    )
    .unwrap();
    let r0 = BigUint::from_bytes_be(&pointlocks::G_HALF_R);
    let twice_r = &r0 * 2u8;
    let inverse = twice_r.modpow(&(&order - 2u8), &order);
    let secp = Secp256k1::new();
    let pools: Vec<_> = (0..pool_count)
        .map(|id| {
            let b = BigUint::from_bytes_be(
                &sha256::Hash::hash(format!("windowed-native-b-{id}").as_bytes()).to_byte_array(),
            ) % &order;
            let offsets: Vec<_> = (0..nkeys)
                .map(|j| {
                    BigUint::from_bytes_be(
                        &sha256::Hash::hash(format!("windowed-native-a-{id}-{j}").as_bytes())
                            .to_byte_array(),
                    ) % (BigUint::from(1u8) << 190)
                })
                .collect();
            let secrets: Vec<_> = offsets
                .iter()
                .map(|a| scalar(&((&b + a * &inverse) % &order)))
                .collect();
            let keys: Vec<_> = secrets
                .iter()
                .map(|s| PublicKey::from_secret_key(&secp, s).serialize().to_vec())
                .collect();
            let script = if batch {
                let specs: Vec<_> = keys.chunks(19).map(|group| (group.to_vec(), 6)).collect();
                layout::batched_multisig_redeem(&specs, CAP)
            } else {
                layout::compact_lookup_redeem(&keys, threshold, CAP)
            };
            Pool {
                b,
                offsets,
                secrets,
                keys,
                script,
            }
        })
        .collect();
    let amount = arg("--funding-amount").parse::<u64>().unwrap();
    let previous = TxOut {
        value: Amount::from_sat(amount),
        script_pubkey: p2tr(),
    };
    let mut funding = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![input(OutPoint {
            txid: bitcoin::Txid::from_str(&arg("--funding-txid")).unwrap(),
            vout: arg("--funding-vout").parse().unwrap(),
        })],
        output: vec![TxOut {
            value: Amount::from_sat(amount - 50_000 - 100_000 * pool_count as u64),
            script_pubkey: p2tr(),
        }],
    };
    for p in &pools {
        funding.output.push(TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: p.script.to_p2wsh(),
        });
    }
    sign_helper(&mut funding, &[previous]);
    let mut spending = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: (0..pool_count + 1)
            .map(|vout| {
                input(OutPoint {
                    txid: funding.compute_txid(),
                    vout: vout as u32,
                })
            })
            .collect(),
        output: std::iter::once(TxOut {
            value: Amount::from_sat(amount - 50_000 - if full { 100_000 } else { 20_000 }),
            script_pubkey: p2tr(),
        })
        .chain((0..pool_count).map(|_| nonce_output(0)))
        .collect(),
    };
    let payload: Vec<u8> = if full {
        (0..8)
            .flat_map(|j| {
                sha256::Hash::hash(format!("windowed256-proof-{j}").as_bytes()).to_byte_array()
            })
            .collect()
    } else {
        vec![]
    };
    let selected: Vec<Vec<usize>> = if full {
        let mut value = BigUint::from_bytes_be(&payload);
        let radix = BigUint::from(choose(keys_per_block, selected_per_block));
        let mut out = vec![];
        for _ in 0..pool_count * blocks {
            let digit = (&value % &radix).iter_u64_digits().next().unwrap_or(0);
            value /= &radix;
            out.push(unrank(digit, keys_per_block, selected_per_block));
        }
        assert_eq!(value, BigUint::from(0u8));
        out.reverse();
        let recovered = out.iter().fold(BigUint::from(0u8), |v, s| {
            v * &radix + rank(s, keys_per_block)
        });
        assert_eq!(recovered, BigUint::from_bytes_be(&payload));
        out.chunks(blocks)
            .map(|group| {
                group
                    .iter()
                    .enumerate()
                    .flat_map(|(b, selected)| selected.iter().map(move |&j| j + b * keys_per_block))
                    .collect()
            })
            .collect()
    } else {
        vec![vec![0, 3, 7], vec![1, 2, 5]]
    };
    let bound = BigUint::from(1u8) << 247; // DER s at most 31 bytes, no sign-padding byte.
    let lower = BigUint::from(1u8) << 239; // DER s exactly 31 bytes, including sign padding.
    let mut pool_reports = vec![];
    for (id, p) in pools.iter().enumerate() {
        let i = id + 1;
        let mut nonce = 0u64;
        let (zbytes, raw_s) = loop {
            spending.output[i] = nonce_output(nonce);
            let zbytes = digest(&spending, i, &p.script, funding.output[i].value);
            let z = BigUint::from_bytes_be(&zbytes) % &order;
            let base = (2u8 * z + &twice_r * &p.b) % &order;
            let raw_s: Vec<_> = p.offsets.iter().map(|a| (&base + a) % &order).collect();
            if raw_s.iter().all(|s| {
                (s >= &lower && s < &bound) || ((&order - s) >= lower && (&order - s) < bound)
            }) {
                break (zbytes, raw_s);
            }
            nonce += 1;
            assert!(nonce < 1_000_000, "reduced-work fixture exceeded bound");
        };
        let signatures: Vec<_> = p
            .secrets
            .iter()
            .map(|key| {
                pointlocks::sign_with_g_half(zbytes, *key, EcdsaSighashType::SinglePlusAnyoneCanPay)
                    .unwrap()
                    .to_vec()
            })
            .collect();
        assert!(signatures.iter().all(|s| s.len() == CAP));
        for ((signature, key), secret) in signatures.iter().zip(&p.keys).zip(&p.secrets) {
            let parsed = bitcoin::ecdsa::Signature::from_slice(signature).unwrap();
            assert_eq!(
                pointlocks::extract_from_g_half(
                    zbytes,
                    &parsed,
                    PublicKey::from_slice(key).unwrap()
                )
                .unwrap(),
                *secret
            );
        }
        let items = if batch {
            let mut items = vec![];
            for block in (0..blocks).rev() {
                items.push(vec![]);
                items.extend(
                    selected[id][block * selected_per_block..(block + 1) * selected_per_block]
                        .iter()
                        .map(|&j| signatures[j].clone()),
                );
            }
            items
        } else {
            layout::lookup_items(&signatures, &p.keys, &selected[id])
        };
        let mut witness = items.clone();
        witness.push(p.script.to_bytes());
        spending.input[i].witness = Witness::from_slice(&witness);
        pool_reports.push(json!({"pool":id,"input_index":i,"n":nkeys,"t":threshold,"cap":CAP,
            "script_hex":hex(p.script.as_bytes()),"script_bytes":p.script.len(),"keys_hex":p.keys.iter().map(|k|hex(k)).collect::<Vec<_>>(),
            "selected":selected[id],"all_signature_hex":signatures.iter().map(|s|hex(s)).collect::<Vec<_>>(),
            "selected_secret_hex":selected[id].iter().map(|&j|hex(&p.secrets[j].secret_bytes())).collect::<Vec<_>>(),
            "native_digest_hex":hex(&zbytes),"nonce":nonce,"hash_trials":nonce+1,
            "negative_low_s_band":raw_s[0]>&order/2u8,"entry_data_items":items.len(),"hint_items":if batch {0} else {threshold},
            "blocks":blocks,"keys_per_block":keys_per_block,"selected_per_block":selected_per_block,"family":if batch {"batched-multisig"} else {"compact-hash-lookup"},
            "complete_witness_items":witness.len(),"serialized_witness_bytes":serialize(&spending.input[i].witness).len()}));
    }
    sign_helper(&mut spending, &funding.output);
    for (id, p) in pools.iter().enumerate() {
        if batch {
            pool_reports[id]["combined_stack_peak"] = Value::Null;
            pool_reports[id]["combined_stack_upper_bound"] =
                json!(blocks * (selected_per_block + 1) + keys_per_block + 5);
            pool_reports[id]["local_execution"]=json!("Not executed: pinned bitcoin-scriptexec lacks CHECKMULTISIG; host ECDSA verification plus Core are required.");
            continue;
        }
        let items: Vec<_> = spending.input[id + 1]
            .witness
            .iter()
            .take(3 * threshold)
            .map(|x| x.to_vec())
            .collect();
        let mut exec = Exec::new(
            ExecCtx::SegwitV0,
            Options::default(),
            TxTemplate {
                tx: spending.clone(),
                prevouts: funding.output.clone(),
                input_idx: id + 1,
                taproot_annex_scriptleaf: None,
            },
            p.script.clone(),
            items,
        )
        .unwrap();
        while exec.exec_next().is_ok() {}
        assert!(exec.result().unwrap().success && exec.stack().len() == 1);
        pool_reports[id]["combined_stack_peak"] = json!(exec.stats().max_nb_stack_items);
        assert_eq!(
            hex(&digest(
                &spending,
                id + 1,
                &p.script,
                funding.output[id + 1].value
            )),
            pool_reports[id]["native_digest_hex"]
        );
    }
    let mut negative = vec![];
    let mut add_case = |name: &str, tx: Transaction| {
        negative.push(json!({"name":name,"expected":false,"transaction":info(&tx)}))
    };
    for name in if full {
        vec![]
    } else {
        vec![
            "oversized-valid-signature",
            "uncommitted-key",
            "duplicate-selection",
            "missing-opening",
            "malformed-signature",
            "wrong-sighash-flag",
            "depth-zero",
            "depth-one",
            "depth-negative",
            "depth-too-large",
            "depth-zero-hash-alias",
            "depth-one-hash-alias",
        ]
    } {
        let mut bad = spending.clone();
        let mut w: Vec<_> = bad.input[1].witness.iter().map(|b| b.to_vec()).collect();
        match name {
            "oversized-valid-signature" => {
                w[0] = pointlocks::sign_with_nonce(
                    digest(&spending, 1, &pools[0].script, funding.output[1].value),
                    pools[0].secrets[selected[0][0]],
                    one(),
                    EcdsaSighashType::SinglePlusAnyoneCanPay,
                )
                .unwrap()
                .to_vec();
                assert!(w[0].len() > CAP);
            }
            "uncommitted-key" => w[1] = pools[1].keys[0].clone(),
            "duplicate-selection" => {
                w[3] = w[0].clone();
                w[4] = w[1].clone();
            }
            "missing-opening" => {
                w.drain(0..3);
            }
            "malformed-signature" => w[0][0] ^= 1,
            "wrong-sighash-flag" => *w[0].last_mut().unwrap() = 3,
            "depth-zero" => w[2] = vec![],
            "depth-one" => w[2] = vec![1],
            "depth-negative" => w[2] = vec![0x81],
            "depth-too-large" => w[2] = vec![127],
            "depth-zero-hash-alias" => {
                w[1] = hash160::Hash::hash(&w[0]).to_byte_array().to_vec();
                w[2] = vec![];
            }
            "depth-one-hash-alias" => {
                w[0] = hash160::Hash::hash(&w[1]).to_byte_array().to_vec();
                w[2] = vec![1];
            }
            _ => unreachable!(),
        }
        bad.input[1].witness = Witness::from_slice(&w);
        add_case(name, bad);
    }
    if !full {
        let mut bad = spending.clone();
        bad.output[1] = nonce_output(pool_reports[0]["nonce"].as_u64().unwrap() + 1);
        sign_helper(&mut bad, &funding.output);
        add_case("changed-native-digest", bad);
    }
    println!("{}",serde_json::to_string_pretty(&json!({"scope":"Reduced-work cap59 native P2WSH functional fixture. Production cap53 work and computational soundness are not established by this test.",
        "compiler":provenance::compiler().unwrap().commit,"interpreter":provenance::interpreter().unwrap().commit,
        "context":"SegwitV0; Options::default; stack limit enabled","production_work_executed":false,
        "offset_bits":190,"test_cap":CAP,"test_s_der_bytes":31,"production_cap":53,"production_s_der_bytes":25,
        "profile":profile,"payload_hex":hex(&payload),"payload_bytes":payload.len(),"pool_count":pool_count,"candidate_count":nkeys*pool_count,"selected_count":threshold*pool_count,
        "funding":info(&funding),"spending":info(&spending),"combined_vbytes":funding.vsize()+spending.vsize(),"pools":pool_reports,"negative_cases":negative})).unwrap());
}
