use crate::support::script::{script, Script};
use bitcoin::hashes::{hash160, Hash};

/// Compute HASH160 of arbitrary bytes, returning a 20-byte array.
pub fn hash160_bytes(data: &[u8]) -> [u8; 20] {
    hash160::Hash::hash(data).to_byte_array()
}

/// Derive the four public-key hashes from four secret preimages.
pub fn lamport_2bit_public_keys(
    preimage0: &[u8],
    preimage1: &[u8],
    preimage2: &[u8],
    preimage3: &[u8],
) -> ([u8; 20], [u8; 20], [u8; 20], [u8; 20]) {
    (
        hash160_bytes(preimage0),
        hash160_bytes(preimage1),
        hash160_bytes(preimage2),
        hash160_bytes(preimage3),
    )
}

/// 2-bit Lamport commitment — verifies the preimage and **leaves the value (0-3) on the stack**.
///
/// Unlocking witness (bottom to top): `<preimage>  <value>`
///
/// Stack trace:
/// ```text
/// [value, preimage, ...]
/// OP_TOALTSTACK        → altstack=[preimage],  main=[value, ...]
/// 3 OP_MIN             → main=[value_clamped, ...]
/// OP_DUP               → main=[value_clamped, value_clamped, ...]
/// OP_TOALTSTACK        → altstack=[value_clamped, preimage], main=[value_clamped, ...]
/// push hash3..hash0    → main=[hash0, hash1, hash2, hash3, value_clamped, ...]
/// OP_FROMALTSTACK      → altstack=[preimage], main=[value_clamped, hash0, hash1, hash2, hash3, value_clamped, ...]
/// OP_ROLL              → pops value_clamped, rolls hash[value_clamped] to top;
///                        main=[hash_v, <3 remaining hashes>, value_clamped, ...]
/// OP_FROMALTSTACK      → altstack=[], main=[preimage, hash_v, <3 remaining>, value_clamped, ...]
/// OP_HASH160           → main=[H(preimage), hash_v, <3 remaining>, value_clamped, ...]
/// OP_EQUALVERIFY       → main=[<3 remaining hashes>, value_clamped, ...]
/// OP_2DROP OP_DROP     → main=[value_clamped, ...]
/// ```
pub fn lamport_2bit_commit(
    hash0: [u8; 20],
    hash1: [u8; 20],
    hash2: [u8; 20],
    hash3: [u8; 20],
) -> Script {
    script! {
        OP_TOALTSTACK
        3 OP_MIN
        OP_DUP
        OP_TOALTSTACK
        { hash3.to_vec() }
        { hash2.to_vec() }
        { hash1.to_vec() }
        { hash0.to_vec() }
        OP_FROMALTSTACK
        OP_ROLL
        OP_FROMALTSTACK
        OP_HASH160
        OP_EQUALVERIFY
        OP_2DROP
        OP_DROP
    }
}

/// 2-bit Lamport reveal — verifies the preimage matches **any** of the four committed hashes.
///
/// Unlocking witness: `<preimage>` (on top of stack).
///
/// Leaves the stack clean (no value left).  The script succeeds iff the preimage
/// hashes to one of hash0..hash3.
pub fn lamport_2bit_reveal(
    hash0: [u8; 20],
    hash1: [u8; 20],
    hash2: [u8; 20],
    hash3: [u8; 20],
) -> Script {
    script! {
        OP_HASH160
        OP_DUP  { hash3.to_vec() } OP_EQUAL
        OP_OVER { hash2.to_vec() } OP_EQUAL OP_BOOLOR
        OP_OVER { hash1.to_vec() } OP_EQUAL OP_BOOLOR
        OP_SWAP { hash0.to_vec() } OP_EQUAL OP_BOOLOR
        OP_VERIFY
        OP_TRUE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::execution::execute_script_with_inputs;
    use bitcoin::script::read_scriptint;

    const PREIMAGES: [&[u8]; 4] = [b"secret0", b"secret1", b"secret2", b"secret3"];

    #[test]
    fn test_commit_all_values() {
        let (h0, h1, h2, h3) =
            lamport_2bit_public_keys(PREIMAGES[0], PREIMAGES[1], PREIMAGES[2], PREIMAGES[3]);
        for value in 0u8..4 {
            let script = lamport_2bit_commit(h0, h1, h2, h3);
            let preimage = PREIMAGES[value as usize].to_vec();
            // Locking script: preimage on top, value below.
            // execute_script_with_inputs: witness[0] pushed first (deepest), witness[last] on top.
            // So: witness[0]=value (deepest/below), witness[1]=preimage (top).
            // Bitcoin Script encodes 0 as [] (empty), 1..=n as [n] with sign bit rules.
            let value_bytes = if value == 0 { vec![] } else { vec![value] };
            let witness = vec![value_bytes, preimage];
            let result = execute_script_with_inputs(script, witness);
            // The script leaves value_clamped on the stack. For value=0, the top is []
            // (empty bytes = Bitcoin Script zero), which is "falsy" so success=false even
            // though the script ran correctly. For value>0, success=true.
            assert!(
                result.error.is_none(),
                "value={} execution error: {:?}",
                value,
                result
            );
            assert_eq!(
                result.final_stack.len(),
                1,
                "value={} stack should have exactly 1 item, got {:?}",
                value,
                result
            );
            // value_clamped should be on top of the stack
            let top = result.final_stack.get(0);
            let got_value = read_scriptint(&top).unwrap_or(-1);
            assert_eq!(
                got_value, value as i64,
                "value on stack wrong for value={}",
                value
            );
        }
    }

    #[test]
    fn test_commit_wrong_preimage_fails() {
        let (h0, h1, h2, h3) =
            lamport_2bit_public_keys(PREIMAGES[0], PREIMAGES[1], PREIMAGES[2], PREIMAGES[3]);
        let script = lamport_2bit_commit(h0, h1, h2, h3);
        // wrong preimage for value 0: value (deepest, encoded as [] for 0), preimage (top)
        let witness = vec![vec![], b"wrong".to_vec()];
        let result = execute_script_with_inputs(script, witness);
        assert!(!result.success, "wrong preimage should fail");
    }

    #[test]
    fn test_reveal_all_values() {
        let (h0, h1, h2, h3) =
            lamport_2bit_public_keys(PREIMAGES[0], PREIMAGES[1], PREIMAGES[2], PREIMAGES[3]);
        for value in 0..4 {
            let script = lamport_2bit_reveal(h0, h1, h2, h3);
            let witness = vec![PREIMAGES[value].to_vec()];
            let result = execute_script_with_inputs(script, witness);
            assert!(result.success, "reveal value={} failed", value);
        }
    }

    #[test]
    fn test_reveal_wrong_preimage_fails() {
        let (h0, h1, h2, h3) =
            lamport_2bit_public_keys(PREIMAGES[0], PREIMAGES[1], PREIMAGES[2], PREIMAGES[3]);
        let script = lamport_2bit_reveal(h0, h1, h2, h3);
        let witness = vec![b"not_a_preimage".to_vec()];
        let result = execute_script_with_inputs(script, witness);
        assert!(!result.success);
    }
}
