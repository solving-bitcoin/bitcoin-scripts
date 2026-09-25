//! Host-side Taproot script-path commitment preflight.
//!
//! A successful result proves only that the revealed script and control block
//! commit to the selected P2TR output. It does not execute the script, validate
//! the transaction, or establish relay-policy acceptance. Future leaf versions
//! can have a valid commitment without being executable as tapscript here.

use bitcoin::{
    secp256k1::{Secp256k1, XOnlyPublicKey},
    taproot::{ControlBlock, LeafVersion, TAPROOT_ANNEX_PREFIX},
    Script, Transaction, TxOut, Witness,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaprootCommitmentError {
    InputIndexOutOfBounds,
    PrevoutCountMismatch,
    NotP2trOutput,
    InvalidOutputKey,
    EmptyWitness,
    KeyPathWitness,
    InvalidControlBlock,
    CommitmentMismatch,
}

/// Verify a complete script-path witness against its P2TR prevout script.
///
/// BIP341's annex, if present as the last item beginning with `0x50`, is
/// removed before selecting the script and control block. The returned leaf
/// version identifies the committed leaf; callers must separately decide
/// whether they support executing that version and validate the script itself.
pub fn verify_taproot_script_path_commitment(
    script_pubkey: &Script,
    witness: &Witness,
) -> Result<LeafVersion, TaprootCommitmentError> {
    if !script_pubkey.is_p2tr() {
        return Err(TaprootCommitmentError::NotP2trOutput);
    }
    let output_key = XOnlyPublicKey::from_slice(&script_pubkey.as_bytes()[2..])
        .map_err(|_| TaprootCommitmentError::InvalidOutputKey)?;

    let mut item_count = witness.len();
    if item_count >= 2 && witness[item_count - 1].first() == Some(&TAPROOT_ANNEX_PREFIX) {
        item_count -= 1;
    }
    if item_count == 0 {
        return Err(TaprootCommitmentError::EmptyWitness);
    }
    if item_count == 1 {
        return Err(TaprootCommitmentError::KeyPathWitness);
    }

    let control = ControlBlock::decode(&witness[item_count - 1])
        .map_err(|_| TaprootCommitmentError::InvalidControlBlock)?;
    let script = Script::from_bytes(&witness[item_count - 2]);
    if !control.verify_taproot_commitment(&Secp256k1::verification_only(), output_key, script) {
        return Err(TaprootCommitmentError::CommitmentMismatch);
    }
    Ok(control.leaf_version)
}

/// Select the witness and prevout from a transaction before checking the
/// script-path commitment. `prevouts` must contain one output per transaction
/// input in input order. This preflight does not check UTXO existence,
/// transaction finality, signature validity, or relay policy.
pub fn verify_taproot_input_commitment(
    tx: &Transaction,
    input_index: usize,
    prevouts: &[TxOut],
) -> Result<LeafVersion, TaprootCommitmentError> {
    let input = tx
        .input
        .get(input_index)
        .ok_or(TaprootCommitmentError::InputIndexOutOfBounds)?;
    if prevouts.len() != tx.input.len() {
        return Err(TaprootCommitmentError::PrevoutCountMismatch);
    }
    verify_taproot_script_path_commitment(&prevouts[input_index].script_pubkey, &input.witness)
}
