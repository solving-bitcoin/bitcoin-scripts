//! Conditional sequence binding for variable common-G sum-lock lookup pools.
//! This does not force a helper/authentication input to exist.
use bitcoin::{
    absolute,
    hashes::{hash160, sha256, Hash},
    secp256k1::SecretKey,
    transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use bitcoin_lab::{
    signatures::pointlocks::sum_key,
    support::{
        provenance,
        script::{script, ScriptCompilation},
    },
};
use bitcoin_scriptexec::{Exec, ExecCtx, Options, TxTemplate};
use serde_json::json;

#[derive(Clone)]
struct Candidate {
    signature: Vec<u8>,
    key: Vec<u8>,
}

fn candidates(n: usize) -> Vec<Candidate> {
    let mut out = vec![];
    let mut counter = 1u64;
    while out.len() < n {
        // Only deterministic public test nonces. Production nonces are secret.
        let nonce =
            SecretKey::from_slice(&sha256::Hash::hash(&counter.to_be_bytes()).to_byte_array())
                .unwrap();
        counter += 1;
        let setup = sum_key::setup_from_nonce(nonce).unwrap();
        if setup.signature().to_vec().len() != 71 {
            continue;
        }
        out.push(Candidate {
            signature: setup.signature().to_vec(),
            key: setup.verification_key.serialize().to_vec(),
        });
    }
    out
}

fn redeem(c: &[Candidate], slots: usize) -> ScriptBuf {
    script! {
        for _ in 0..3*slots { OP_TOALTSTACK }
        { sum_key::generator_key().serialize().to_vec() }
        for row in c { { hash160::Hash::hash(&row.key).to_byte_array().to_vec() } }
        for j in 0..slots {
            OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK
            if j>0 {
                OP_DUP OP_NOTIF
                OP_2DROP OP_2DROP
                { slots-j } OP_CSV OP_DROP
                OP_ELSE
            }
            OP_DUP 2 { c.len()-j+2 } OP_WITHIN OP_VERIFY
            OP_ROLL OP_OVER OP_HASH160 OP_EQUALVERIFY
            OP_OVER OP_SIZE 57 OP_GREATERTHAN OP_VERIFY
            { c.len()-j+2 } OP_PICK OP_CHECKSIGVERIFY OP_CHECKSIGVERIFY
            if j>0 { OP_ENDIF }
        }
        for _ in 0..c.len()-slots+1 { OP_DROP }
        OP_TRUE
    }
    .compile_with_policy()
}

fn items(c: &[Candidate], selected: &[usize], slots: usize) -> Vec<Vec<u8>> {
    let mut remaining: Vec<_> = (0..c.len()).collect();
    let mut out = vec![];
    for &index in selected {
        let position = remaining.iter().position(|&x| x == index).unwrap();
        let depth = remaining.len() + 1 - position;
        remaining.remove(position);
        out.extend([
            c[index].signature.clone(),
            c[index].key.clone(),
            vec![depth as u8],
        ]);
    }
    out.resize(3 * slots, vec![]);
    out
}

fn execute(script: &ScriptBuf, opening: Vec<Vec<u8>>, sequence: u32) -> (bool, usize) {
    let tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: (0..2)
            .map(|vout| TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::all_zeros(),
                    vout,
                },
                script_sig: ScriptBuf::new(),
                sequence: if vout == 1 {
                    Sequence(sequence)
                } else {
                    Sequence::MAX
                },
                witness: Witness::new(),
            })
            .collect(),
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new(),
        }],
    };
    let mut exec = Exec::new(
        ExecCtx::Legacy,
        Options::default(),
        TxTemplate {
            tx,
            prevouts: vec![],
            input_idx: 1,
            taproot_annex_scriptleaf: None,
        },
        script.clone(),
        opening,
    )
    .unwrap();
    while exec.exec_next().is_ok() {}
    (
        exec.result().unwrap().success && exec.stack().len() == 1,
        exec.stats().max_nb_stack_items,
    )
}

fn script_sig(opening: &[Vec<u8>], redeem: &ScriptBuf) -> ScriptBuf {
    let mut builder = bitcoin::script::Builder::new();
    for item in opening {
        builder = if item.is_empty() {
            builder.push_int(0)
        } else if item.len() == 1 && (1..=16).contains(&item[0]) {
            builder.push_int(item[0] as i64)
        } else {
            builder.push_slice(bitcoin::script::PushBytesBuf::try_from(item.clone()).unwrap())
        };
    }
    builder
        .push_slice(bitcoin::script::PushBytesBuf::try_from(redeem.to_bytes()).unwrap())
        .into_script()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let c = candidates(15);
    let slots = 5;
    let script = redeem(&c, slots);
    assert!(script.len() <= 520);
    let mut cases = vec![];
    let mut sizes = vec![];
    let mut peak = 0;
    for count in 1..=slots {
        let selected: Vec<_> = (0..count).collect();
        let opening = items(&c, &selected, slots);
        let sequence = (slots - count) as u32;
        let (ok, p) = execute(&script, opening.clone(), sequence);
        assert!(ok);
        peak = peak.max(p);
        sizes.push(script_sig(&opening, &script).len());
        let mut variants = vec![("valid", opening.clone(), sequence, true)];
        if count > 1 {
            let fewer = items(&c, &selected[..count - 1], slots);
            variants.push((
                "removed-revelation-fixed-sequence",
                fewer.clone(),
                sequence,
                false,
            ));
            variants.push((
                "removed-revelation-raised-sequence",
                fewer,
                sequence + 1,
                true,
            ));
        }
        if count < slots {
            variants.push((
                "sequence-disable-flag",
                opening.clone(),
                sequence | (1 << 31),
                false,
            ));
            variants.push((
                "sequence-time-flag",
                opening.clone(),
                sequence | (1 << 22),
                false,
            ));
            variants.push(("sequence-too-low", opening.clone(), sequence - 1, false));
        }
        variants.push(("all-empty", vec![vec![]; 3 * slots], sequence, false));
        for (name, opening, sequence, expected) in variants {
            assert_eq!(
                execute(&script, opening.clone(), sequence).0,
                expected,
                "count={count} {name}"
            );
            cases.push(json!({
                "name":format!("sum-lookup-csv-5-of-15-t{count}-{name}"),
                "variant":"sum-key-hash160-lookup-csv","n":15,"t":count,"max_t":slots,
                "expected":expected,"expected_policy":expected,"locked_sequence":sequence,
                "script_hex":hex(script.as_bytes()),"items_hex":opening.iter().map(|x|hex(x)).collect::<Vec<_>>(),
                "p2sh_script_sig_hex":hex(script_sig(&opening,&script).as_bytes()),"hint_items":slots,
            }));
        }
    }
    let ops = script
        .instructions()
        .filter(|i| matches!(i,Ok(bitcoin::script::Instruction::Op(op)) if op.to_u8()>0x60))
        .count();
    println!("{}",serde_json::to_string_pretty(&json!({
        "compiler":provenance::compiler().unwrap().commit,"interpreter":provenance::interpreter().unwrap().commit,
        "evidence":"locally-reproduced","deployment":"unclassified",
        "script_bytes":script.len(),"script_sig_bytes_by_t":sizes,"hint_items":slots,"entry_items":3*slots,
        "combined_stack_peak":peak,"static_non_push_ops":ops,"static_sigops":2*slots,
        "condition":"Must retain unavoidable authorization binding every input sequence; this script does not require the helper to be present",
        "core_requirement":"Funding maturity for relative sequence value4; locked_sequence row metadata; version2",
        "funding_maturity_blocks":4,
        "cases":cases,
    })).unwrap());
}
