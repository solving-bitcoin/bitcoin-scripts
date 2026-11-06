use bitcoin::{
    absolute,
    hashes::{hash160, Hash},
    script::Instruction,
    secp256k1::{Keypair, Message, Secp256k1, SecretKey},
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::{LeafVersion, TaprootBuilder},
    transaction, Amount, OutPoint, ScriptBuf, TapLeafHash, Transaction, TxIn, TxOut, Txid, Witness,
};
use bitcoin_lab::support::{script::*, taproot::verify_taproot_input_commitment};
use bitcoin_scriptexec::{Exec, Experimental, Options, TxTemplate};

mod schedule {
    include!("../../src/signatures/hash_keyset/schedule.rs");
}

pub struct Spend {
    pub leaf: ScriptBuf,
    tx: Transaction,
    prevout: TxOut,
    control: Vec<u8>,
}

pub struct Trace {
    pub success: bool,
    pub peak: usize,
    pub executed: usize,
    pub initial_budget: i64,
    pub charged: i64,
}

pub fn keypairs(count: usize) -> Vec<Keypair> {
    let secp = Secp256k1::new();
    (1..=count)
        .map(|i| {
            let mut bytes = [0; 32];
            bytes[28..].copy_from_slice(&(i as u32).to_be_bytes());
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&bytes).unwrap())
        })
        .collect()
}

pub fn public_key(keypair: &Keypair) -> [u8; 32] {
    keypair.x_only_public_key().0.serialize()
}

pub fn identifier(bytes: &[u8]) -> [u8; 20] {
    hash160::Hash::hash(bytes).to_byte_array()
}

pub fn embedded_scan(keys: &[[u8; 32]]) -> Script {
    script! { { schedule::verify_any_match(keys) } OP_CHECKSIGVERIFY }
}

pub fn embedded_index(keys: &[[u8; 32]]) -> Script {
    if let [key] = keys {
        return script! { { key.to_vec() } OP_CHECKSIGVERIFY };
    }
    script! {
        OP_DUP 0 { keys.len() } OP_WITHIN OP_VERIFY OP_TOALTSTACK
        for key in keys.iter().rev() { { key.to_vec() } }
        OP_FROMALTSTACK OP_ROLL OP_TOALTSTACK
        for _ in 1..keys.len() { OP_DROP }
        OP_FROMALTSTACK OP_CHECKSIGVERIFY
    }
}

impl Spend {
    pub fn new(fragment: Script) -> Self {
        let leaf = script! { { fragment } OP_TRUE }.compile_with_policy();
        let secp = Secp256k1::new();
        let internal =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[0xc3; 32]).unwrap())
                .x_only_public_key()
                .0;
        let info = TaprootBuilder::new()
            .add_leaf(0, leaf.clone())
            .unwrap()
            .finalize(&secp, internal)
            .unwrap();
        let control = info
            .control_block(&(leaf.clone(), LeafVersion::TapScript))
            .unwrap()
            .serialize();
        let prevout = TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: ScriptBuf::new_p2tr_tweaked(info.output_key()),
        };
        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([0x22; 32]),
                    vout: 0,
                },
                ..Default::default()
            }],
            output: vec![TxOut {
                value: Amount::from_sat(90_000),
                script_pubkey: prevout.script_pubkey.clone(),
            }],
        };
        Self {
            leaf,
            tx,
            prevout,
            control,
        }
    }

    pub fn sign(&self, key: &Keypair, sighash_type: TapSighashType) -> Vec<u8> {
        let hash = SighashCache::new(&self.tx)
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(std::slice::from_ref(&self.prevout)),
                TapLeafHash::from_script(&self.leaf, LeafVersion::TapScript),
                sighash_type,
            )
            .unwrap();
        let mut signature = Secp256k1::new()
            .sign_schnorr_no_aux_rand(&Message::from_digest(hash.to_byte_array()), key)
            .as_ref()
            .to_vec();
        if sighash_type != TapSighashType::Default {
            signature.push(sighash_type as u8);
        }
        signature
    }

    pub fn witness(&self, mut data: Vec<Vec<u8>>) -> Witness {
        data.extend([self.leaf.to_bytes(), self.control.clone()]);
        Witness::from_slice(&data)
    }

    pub fn trace(&self, witness: Witness) -> Trace {
        let mut tx = self.tx.clone();
        tx.input[0].witness = witness;
        let prevouts = std::slice::from_ref(&self.prevout);
        assert_eq!(
            verify_taproot_input_commitment(&tx, 0, prevouts),
            Ok(LeafVersion::TapScript)
        );
        let mut exec = Exec::new_tapscript(
            Options {
                require_minimal: false,
                enforce_stack_limit: true,
                experimental: Experimental { op_cat: false },
                ..Default::default()
            },
            TxTemplate {
                tx,
                prevouts: prevouts.to_vec(),
                input_idx: 0,
                taproot_annex_scriptleaf: None,
            },
        )
        .unwrap();
        let mut executed = 0;
        loop {
            let next = exec.remaining_script().instructions().next();
            let non_push = matches!(next, Some(Ok(Instruction::Op(op))) if op.to_u8() > 0x60);
            if exec.exec_next().is_err() {
                break;
            }
            executed += usize::from(non_push);
        }
        let success = exec.result().unwrap().success;
        if success {
            assert_eq!(exec.stack().len(), 1);
            assert_eq!(exec.stack().get(0), vec![1]);
        }
        let stats = exec.stats();
        Trace {
            success,
            peak: stats.max_nb_stack_items,
            executed,
            initial_budget: stats.start_validation_weight,
            charged: stats.start_validation_weight - stats.validation_weight,
        }
    }
}
