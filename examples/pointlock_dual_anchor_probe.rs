//! Negative-result fixture: public dynamic recovery keys do not lock log(T).
//! The long high-S signature reuses the public anchor equation.
use bitcoin::{
    hashes::{sha256, Hash},
    secp256k1::{PublicKey, Secp256k1, SecretKey},
};
use bitcoin_lab::support::{
    provenance,
    script::{script, ScriptCompilation},
};
use serde_json::json;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let (target, attempt) = (0u32..)
        .find_map(|i| {
            let mut x = sha256::Hash::hash(format!("dual-anchor/public-coordinate/{i}").as_bytes())
                .to_byte_array();
            // A 32-byte unsigned DER r. This is hash-to-x, not scalar-to-G.
            x[0] = (x[0] & 0x3f) | 0x10;
            let mut encoded = vec![2];
            encoded.extend(x);
            PublicKey::from_slice(&encoded).ok().map(|p| (p, i))
        })
        .unwrap();
    let mut tau = vec![0x30, 0x25, 0x02, 0x20];
    tau.extend(&target.serialize()[1..]);
    tau.extend([0x02, 0x01, 0x01, 0x01]);
    assert_eq!(tau.len(), 40);
    let mut one = [0u8; 32];
    one[31] = 1;
    let owner =
        PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&one).unwrap());
    // Entry: sigma P Q authorization. All checks have the same scriptCode.
    let code = script! {
        {owner.serialize().to_vec()} OP_CHECKSIGVERIFY
        OP_SIZE 33 OP_EQUALVERIFY OP_SWAP
        OP_SIZE 33 OP_EQUALVERIFY OP_SWAP
        OP_2DUP OP_EQUAL OP_NOT OP_VERIFY
        {tau.clone()} OP_2 OP_PICK OP_CHECKSIGVERIFY
        {tau.clone()} OP_OVER OP_CHECKSIGVERIFY
        OP_ROT OP_SIZE 57 OP_GREATERTHAN OP_VERIFY
        OP_DUP OP_3 OP_PICK OP_CHECKSIGVERIFY
        OP_SWAP OP_CHECKSIGVERIFY OP_DROP OP_TRUE
    }
    .compile_with_policy();
    println!("{}", serde_json::to_string_pretty(&json!({
        "scope":"Negative-result dual dynamic anchor fixture; no target scalar supplied or computed.",
        "target_hex":hex(&target.serialize()), "target_coordinate_attempt":attempt,
        "tau_hex":hex(&tau), "script_hex":hex(code.as_bytes()), "script_bytes":code.len(),
        "hint_items":0, "entry_items":4, "complete_witness_items":5,
        "compiler_commit":provenance::compiler().unwrap().commit,
        "interpreter_commit":provenance::interpreter().unwrap().commit,
    })).unwrap());
}
