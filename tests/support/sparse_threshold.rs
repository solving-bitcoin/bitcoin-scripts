use bitcoin::{
    absolute,
    hashes::Hash,
    script::Instruction,
    secp256k1::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey},
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::{LeafVersion, TaprootBuilder},
    transaction, Address, Amount, Network, OutPoint, ScriptBuf, Sequence, TapLeafHash, Transaction,
    TxIn, TxOut, Txid, Witness,
};
use bitcoin_lab::{
    signatures::sparse_threshold::verify_sparse_threshold,
    support::{script::*, taproot::verify_taproot_input_commitment},
};
use bitcoin_scriptexec::{Exec, ExecError, Experimental, Options, TxTemplate};

pub struct Fixture {
    pub tx: Transaction,
    pub prevout: TxOut,
    pub script: ScriptBuf,
    pub data: Vec<Vec<u8>>,
    pub raw_script_bytes: usize,
    control: Vec<u8>,
}

pub struct Trace {
    pub success: bool,
    pub error: Option<ExecError>,
    pub peak: usize,
    pub executed: usize,
    pub initial_budget: i64,
    pub charged: i64,
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

fn dense(keys: &[XOnlyPublicKey], threshold: usize) -> Script {
    script! {
        for (index, key) in keys.iter().rev().enumerate() {
            {key.serialize().to_vec()}
            if index == 0 { OP_CHECKSIG } else { OP_CHECKSIGADD }
        }
        {threshold} OP_NUMEQUAL
    }
}

fn num(value: i64) -> Vec<u8> {
    let mut bytes = [0; 8];
    let len = bitcoin::script::write_scriptint(&mut bytes, value);
    bytes[..len].to_vec()
}

pub fn fixture(n: usize, depths: &[usize], sparse: bool) -> Fixture {
    let secp = Secp256k1::new();
    let pairs = keypairs(n);
    let keys: Vec<_> = pairs.iter().map(|key| key.x_only_public_key().0).collect();
    let leaf = if sparse {
        script! {{verify_sparse_threshold(&keys, depths.len())} OP_TRUE}
    } else {
        dense(&keys, depths.len())
    };
    let raw_script_bytes = leaf.len();
    let script = leaf.compile_with_policy();
    let internal = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[0xc3; 32]).unwrap())
        .x_only_public_key()
        .0;
    let output = TaprootBuilder::new()
        .add_leaf(0, script.clone())
        .unwrap()
        .finalize(&secp, internal)
        .unwrap();
    let control = output
        .control_block(&(script.clone(), LeafVersion::TapScript))
        .unwrap();
    let prevout = TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: Address::p2tr_tweaked(output.output_key(), Network::Regtest).script_pubkey(),
    };
    let tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([0x22; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(90_000),
            script_pubkey: prevout.script_pubkey.clone(),
        }],
    };
    let leaf_hash = TapLeafHash::from_script(&script, LeafVersion::TapScript);
    let sighash = SighashCache::new(&tx)
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(std::slice::from_ref(&prevout)),
            leaf_hash,
            TapSighashType::Default,
        )
        .unwrap();
    let message = Message::from_digest(sighash.to_byte_array());
    let sign = |depth: usize| {
        secp.sign_schnorr_no_aux_rand(&message, &pairs[n - 1 - depth])
            .as_ref()
            .to_vec()
    };
    let data = if sparse {
        depths
            .iter()
            .rev()
            .flat_map(|&depth| [sign(depth), num(depth as i64)])
            .collect()
    } else {
        let mut data = vec![vec![]; n];
        for &depth in depths {
            data[n - 1 - depth] = sign(depth);
        }
        data
    };
    let mut fixture = Fixture {
        tx,
        prevout,
        script,
        data,
        raw_script_bytes,
        control: control.serialize(),
    };
    fixture.tx = fixture.with_data(fixture.data.clone());
    fixture
}

impl Fixture {
    pub fn with_data(&self, mut data: Vec<Vec<u8>>) -> Transaction {
        data.extend([self.script.to_bytes(), self.control.clone()]);
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
            let instruction = exec.remaining_script().instructions().next();
            let counted = matches!(instruction, Some(Ok(Instruction::Op(op))) if op.to_u8() > 0x60);
            if exec.exec_next().is_err() {
                break;
            }
            executed += usize::from(counted);
        }
        let result = exec.result().unwrap();
        let stats = exec.stats();
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
