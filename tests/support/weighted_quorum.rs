use bitcoin::{
    absolute,
    hashes::Hash,
    script::Instruction,
    secp256k1::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey},
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::{LeafVersion, TaprootBuilder},
    transaction, Amount, OutPoint, ScriptBuf, TapLeafHash, Transaction, TxIn, TxOut, Txid, Witness,
};
use bitcoin_lab::{
    arithmetic::scriptint::mul_by_constant,
    support::{script::*, taproot::verify_taproot_input_commitment},
};
use bitcoin_scriptexec::{Exec, ExecError, Experimental, Options, TxTemplate};

pub struct Trace {
    pub success: bool,
    pub error: Option<ExecError>,
    pub peak: usize,
    pub executed: usize,
    pub initial_budget: i64,
    pub charged: i64,
}

pub struct Spend {
    pub leaf: ScriptBuf,
    pub raw_script_bytes: usize,
    tx: Transaction,
    prevout: TxOut,
    control: Vec<u8>,
    signatures: Vec<Vec<u8>>,
}

pub fn keypairs(n: usize) -> Vec<Keypair> {
    let secp = Secp256k1::new();
    (1..=n)
        .map(|i| {
            let mut bytes = [0; 32];
            bytes[28..].copy_from_slice(&(i as u32).to_be_bytes());
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&bytes).unwrap())
        })
        .collect()
}

pub fn groups<'a>(
    keys: &'a [XOnlyPublicKey],
    spec: &[(u32, usize)],
) -> Vec<(u32, &'a [XOnlyPublicKey])> {
    let mut remaining = keys;
    let groups = spec
        .iter()
        .map(|&(weight, n)| {
            let (group, rest) = remaining.split_at(n);
            remaining = rest;
            (weight, group)
        })
        .collect();
    assert!(remaining.is_empty());
    groups
}

pub fn individual(groups: &[(u32, &[XOnlyPublicKey])], threshold: u32) -> Script {
    script! {
        0
        for (weight, keys) in groups {
            for key in keys.iter() {
                OP_SWAP {key.serialize().to_vec()} OP_CHECKSIG
                {mul_by_constant(*weight)} OP_ADD
            }
        }
        {threshold} OP_GREATERTHANOREQUAL OP_VERIFY
    }
}

impl Spend {
    pub fn new(fragment: Script, keys: &[Keypair]) -> Self {
        let script = script! {{fragment} OP_TRUE};
        let raw_script_bytes = script.len();
        let leaf = script.compile_with_policy();
        let secp = Secp256k1::new();
        let internal =
            Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[0xc3; 32]).unwrap())
                .x_only_public_key()
                .0;
        let spend = TaprootBuilder::new()
            .add_leaf(0, leaf.clone())
            .unwrap()
            .finalize(&secp, internal)
            .unwrap();
        let control = spend
            .control_block(&(leaf.clone(), LeafVersion::TapScript))
            .unwrap()
            .serialize();
        let prevout = TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: ScriptBuf::new_p2tr_tweaked(spend.output_key()),
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
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        let sighash = SighashCache::new(&tx)
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(std::slice::from_ref(&prevout)),
                leaf_hash,
                TapSighashType::Default,
            )
            .unwrap();
        let message = Message::from_digest(sighash.to_byte_array());
        let signatures = keys
            .iter()
            .map(|key| {
                secp.sign_schnorr_no_aux_rand(&message, key)
                    .as_ref()
                    .to_vec()
            })
            .collect();
        Self {
            leaf,
            raw_script_bytes,
            tx,
            prevout,
            control,
            signatures,
        }
    }

    pub fn data(&self, indices: &[usize]) -> Vec<Vec<u8>> {
        let n = self.signatures.len();
        let mut data = vec![vec![]; n];
        for &index in indices {
            data[n - 1 - index] = self.signatures[index].clone();
        }
        data
    }

    pub fn with_data(&self, mut data: Vec<Vec<u8>>) -> Transaction {
        data.extend([self.leaf.to_bytes(), self.control.clone()]);
        let mut tx = self.tx.clone();
        tx.input[0].witness = Witness::from_slice(&data);
        tx
    }

    pub fn trace(&self, tx: &Transaction) -> Trace {
        let prevouts = std::slice::from_ref(&self.prevout);
        assert_eq!(
            verify_taproot_input_commitment(tx, 0, prevouts),
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
                tx: tx.clone(),
                prevouts: prevouts.to_vec(),
                input_idx: 0,
                taproot_annex_scriptleaf: None,
            },
        )
        .unwrap();
        let mut executed = 0;
        loop {
            let next = exec.remaining_script().instructions().next();
            let non_push = matches!(next,Some(Ok(Instruction::Op(op))) if op.to_u8()>0x60);
            if exec.exec_next().is_err() {
                break;
            }
            executed += usize::from(non_push);
        }
        let result = exec.result().unwrap();
        let stats = exec.stats();
        if result.success {
            assert_eq!(exec.stack().len(), 1);
            assert_eq!(exec.stack().get(0), vec![1]);
        }
        Trace {
            success: result.success,
            error: result.error.clone(),
            peak: stats.max_nb_stack_items,
            executed,
            initial_budget: stats.start_validation_weight,
            charged: stats.start_validation_weight - stats.validation_weight,
        }
    }
}
