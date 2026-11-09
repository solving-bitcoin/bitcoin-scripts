//! Deterministic Taproot leaves for the funded wide-ScriptNum comparison.
use bitcoin::{
    hex::DisplayHex,
    secp256k1::{Keypair, Secp256k1, SecretKey},
    taproot::{LeafVersion, TaprootBuilder},
    Address, Network,
};
use bitcoin_lab::{
    arithmetic::{scriptint::MAX_SCRIPTNUM, sum_equality::verify_equal_sums},
    support::{
        provenance,
        script::*,
        tapscript::{execute_tapscript, TapscriptProfile},
    },
};
use serde_json::json;

mod baseline {
    use bitcoin_lab::support::script::*;
    include!("../research/wide-scriptnum-equality/baseline.rs");
}

fn num(value: i64) -> Vec<u8> {
    let mut bytes = [0; 8];
    let len = bitcoin::script::write_scriptint(&mut bytes, value);
    bytes[..len].to_vec()
}

fn main() {
    let raw = verify_equal_sums();
    let limbs = baseline::verify_equal_sums_with_limbs();
    let numeric = script! {
        OP_ADD OP_TOALTSTACK OP_ADD OP_FROMALTSTACK OP_NUMEQUALVERIFY
    };
    let max = i64::from(MAX_SCRIPTNUM);
    let inputs = |values: [i64; 4]| values.map(num).to_vec();
    let positive = inputs([max; 4]);
    let negative = inputs([-max; 4]);
    let secp = Secp256k1::new();
    let key = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[41; 32]).unwrap())
        .x_only_public_key()
        .0;
    let mut fixtures = Vec::new();
    for (name, fragment, data, expected) in [
        ("raw-positive", &raw, positive.clone(), [true, true]),
        ("raw-negative", &raw, negative.clone(), [true, true]),
        (
            "raw-unequal",
            &raw,
            inputs([max, max, max, max - 1]),
            [false, false],
        ),
        (
            "raw-negative-zero-alias",
            &raw,
            vec![vec![0x80], vec![], vec![], vec![]],
            [true, false],
        ),
        ("limbs-positive", &limbs, positive.clone(), [true, true]),
        ("limbs-negative", &limbs, negative.clone(), [true, true]),
        ("numeric-positive", &numeric, positive, [false, false]),
        ("numeric-negative", &numeric, negative, [false, false]),
    ] {
        let script = script! {{fragment.clone()} OP_TRUE}.compile_with_policy();
        let output = TaprootBuilder::new()
            .add_leaf(0, script.clone())
            .unwrap()
            .finalize(&secp, key)
            .unwrap();
        let control = output
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .unwrap();
        let address = Address::p2tr_tweaked(output.output_key(), Network::Regtest);
        let local = [TapscriptProfile::Consensus, TapscriptProfile::Policy].map(|profile| {
            let result = execute_tapscript(script.clone(), data.clone(), profile);
            let execution = result.execution().unwrap();
            json!({
                "accepted": execution.success,
                "error": execution.error.as_ref().map(|error| format!("{error:?}")),
            })
        });
        fixtures.push(json!({
            "name": name,
            "script_pubkey": address.script_pubkey().as_bytes().to_lower_hex_string(),
            "witness": data.iter().map(|item| item.to_lower_hex_string())
                .chain([script.as_bytes().to_lower_hex_string(), control.serialize().to_lower_hex_string()])
                .collect::<Vec<_>>(),
            "expected": expected,
            "local": local,
        }));
    }
    let mining_script = script! {OP_TRUE}.compile_with_policy();
    println!(
        "{}",
        json!({
            "mining_address": Address::p2wsh(&mining_script, Network::Regtest).to_string(),
            "compiler": provenance::compiler().unwrap().source,
            "interpreter": provenance::interpreter().unwrap().source,
            "fixtures": fixtures,
        })
    );
}
