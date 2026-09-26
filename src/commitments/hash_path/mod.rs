//! Hash-path commitments to bit strings and 1–31-bit Script integers.
//!
//! The 20-byte output of one path can be used as the preimage of another. This
//! gives protocols an ordered, append-like hash-state composition even though
//! Bitcoin Script cannot concatenate arbitrary byte strings. Each step ends in
//! RIPEMD-160; nesting equals processing the joined bit path.
//!
//! WARNING: the starting preimage must be independently bound. Otherwise
//! `(x, true)` and `(SHA256(x), false)` open the same digest (NR-056).

use bitcoin::hashes::{ripemd160, sha256, Hash};

use crate::support::script::{script, Script};

/// Largest bit width that can be reconstructed as a positive four-byte
/// Script integer.
pub const MAX_INTEGER_BITS: usize = 31;

/// Compute the hash-path commitment for `bits`, starting from `preimage`.
///
/// Bits are processed in slice order; the integer helper supplies them
/// least-significant first. A false bit applies RIPEMD-160; a true bit applies
/// RIPEMD160(SHA256(state)). No terminal hash is added. This changes commitments
/// produced by the former SHA256/RIPEMD160 branch construction.
/// Panics for an empty path, matching the script generator.
pub fn hash_path_commitment(preimage: &[u8], bits: &[bool]) -> [u8; 20] {
    assert!(!bits.is_empty(), "bit_width must be non-zero");
    let mut state = preimage.to_vec();
    for bit in bits {
        if *bit {
            state = sha256::Hash::hash(&state).to_byte_array().to_vec();
        }
        state = ripemd160::Hash::hash(&state).to_byte_array().to_vec();
    }
    state.try_into().expect("every step produces 20 bytes")
}

/// Compute a commitment to the low `bit_width` bits of `value`.
///
/// Panics unless `bit_width` is in `1..=31` and `value < 2^bit_width`.
pub fn hash_path_integer_commitment(preimage: &[u8], value: u32, bit_width: usize) -> [u8; 20] {
    let bits = integer_bits(value, bit_width);
    hash_path_commitment(preimage, &bits)
}

/// Build the canonical witness for [`verify_hash_path_to_integer`].
///
/// The returned vector is in witness serialization order: the most
/// significant bit is deepest, bit zero is immediately below `preimage`, and
/// `preimage` is the top item.
pub fn hash_path_integer_witness(preimage: &[u8], value: u32, bit_width: usize) -> Vec<Vec<u8>> {
    let bits = integer_bits(value, bit_width);
    let mut witness = bits
        .iter()
        .rev()
        .map(|bit| if *bit { vec![1] } else { vec![] })
        .collect::<Vec<_>>();
    witness.push(preimage.to_vec());
    witness
}

fn integer_bits(value: u32, bit_width: usize) -> Vec<bool> {
    assert_integer_width(bit_width);
    assert!(
        value < (1u32 << bit_width),
        "value does not fit in bit_width"
    );
    (0..bit_width)
        .map(|index| value & (1u32 << index) != 0)
        .collect()
}

fn assert_integer_width(bit_width: usize) {
    assert!(
        (1..=MAX_INTEGER_BITS).contains(&bit_width),
        "bit_width must be in 1..={MAX_INTEGER_BITS}"
    );
}

/// Compute a `bit_width`-step hash path from a preimage on top of the stack.
///
/// Stack before (top first): `preimage, bit0, ..., bitN-1`.
/// Stack after: `commitment`.
///
/// Selectors follow OP_IF truthiness. Tapscript requires `[]` or `[1]`;
/// legacy accepts noncanonical selectors. Retained bits are always normalized.
pub fn hash_path_script(bit_width: usize) -> Script {
    assert!(bit_width > 0, "bit_width must be non-zero");
    hash_path_script_inner(bit_width, false)
}

fn hash_path_script_inner(bit_width: usize, save_bits: bool) -> Script {
    script! {
        for _ in 0..bit_width {
            OP_SWAP

            OP_IF
                OP_SHA256
                if save_bits { OP_1 }
            if save_bits {
                OP_ELSE
                OP_0
            }
            OP_ENDIF
            if save_bits { OP_TOALTSTACK }
            OP_RIPEMD160
        }
    }
}

/// Verify a generic hash path and consume the preimage and all input bits.
///
/// Leaves true on success. `bit_width` has no Script-integer restriction, but
/// the enclosing script's stack, opcode, and execution limits still apply.
pub fn verify_hash_path(bit_width: usize, commitment: [u8; 20]) -> Script {
    script! {
        { hash_path_script(bit_width) }
        { commitment.to_vec() }
        OP_EQUALVERIFY
        OP_1
    }
}

/// Verify two ordered hash paths without serializing the intermediate digest.
///
/// The first path's digest is duplicated, checked against `first_commitment`,
/// and then consumed as the second path's preimage. Witness order is
/// `second_bitN-1 ... second_bit0 first_bitN-1 ... first_bit0 first_preimage`.
pub fn verify_hash_path_chain(
    first_bit_width: usize,
    first_commitment: [u8; 20],
    second_bit_width: usize,
    second_commitment: [u8; 20],
) -> Script {
    script! {
        { hash_path_script(first_bit_width) }
        OP_DUP
        { first_commitment.to_vec() }
        OP_EQUALVERIFY
        { hash_path_script(second_bit_width) }
        { second_commitment.to_vec() }
        OP_EQUAL
    }
}

/// Verify a generic hash path and save its bits on the altstack.
///
/// Leaves true on the main stack. After verification, bit `N-1` is on top of
/// the altstack and bit zero is deepest. These are canonical branch results,
/// never copies of untrusted selector bytes. Use these bits for later binding.
pub fn verify_hash_path_to_altstack(bit_width: usize, commitment: [u8; 20]) -> Script {
    assert!(bit_width > 0, "bit_width must be non-zero");
    script! {
        { hash_path_script_inner(bit_width, true) }
        { commitment.to_vec() }
        OP_EQUALVERIFY
        OP_1
    }
}

/// Verify a hash-path commitment and return its committed integer.
///
/// Stack before (top first): `preimage, bit0, ..., bitN-1`.
/// Stack after: the non-negative Script integer represented by those bits.
/// `bit_width` must be in `1..=31`.
pub fn verify_hash_path_to_integer(bit_width: usize, commitment: [u8; 20]) -> Script {
    assert_integer_width(bit_width);
    script! {
        { hash_path_script_inner(bit_width, true) }
        { commitment.to_vec() }
        OP_EQUALVERIFY

        0
        for _ in 0..bit_width {
            // Bits leave the altstack from most to least significant.
            OP_FROMALTSTACK
            OP_SWAP OP_DUP OP_ADD OP_ADD
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::{execution::execute_script_with_inputs, script::script};

    use crate::support::script::ScriptCompilation;
    use bitcoin_scriptexec::{Exec, ExecCtx, Options, TxTemplate};

    fn legacy_success(script: Script, witness: Vec<Vec<u8>>) -> bool {
        let mut exec = Exec::new(
            ExecCtx::Legacy,
            Options {
                verify_minimal_if: false,
                ..Default::default()
            },
            TxTemplate {
                tx: bitcoin::Transaction {
                    version: bitcoin::transaction::Version::TWO,
                    lock_time: bitcoin::absolute::LockTime::ZERO,
                    input: vec![],
                    output: vec![],
                },
                prevouts: vec![],
                input_idx: 0,
                taproot_annex_scriptleaf: None,
            },
            script.compile_with_policy(),
            witness,
        )
        .unwrap();
        while exec.exec_next().is_ok() {}
        exec.result().unwrap().success
    }

    fn counted_ops(script: Script) -> usize {
        script
            .compile_with_policy()
            .instructions()
            .map(|i| match i.unwrap() {
                bitcoin::script::Instruction::Op(op) if op.to_u8() > 0x60 => 1,
                _ => 0,
            })
            .sum()
    }

    #[test]
    fn static_opcode_costs() {
        for n in [1, 8, 28, 31, 39] {
            assert_eq!(counted_ops(hash_path_script(n)), 5 * n);
            assert_eq!(counted_ops(hash_path_script_inner(n, true)), 7 * n);
        }
    }

    #[test]
    fn exhaustive_eight_bit_paths_and_retained_order() {
        for value in 0..256 {
            let bits = integer_bits(value, 8);
            let preimage = b"deterministic hash-path test";
            let commitment = hash_path_commitment(preimage, &bits);
            let witness = hash_path_integer_witness(preimage, value, 8);
            assert!(legacy_success(
                verify_hash_path(8, commitment),
                witness.clone()
            ));
            assert!(legacy_success(
                script! {
                    { verify_hash_path_to_altstack(8, commitment) }
                    for bit in bits.iter().rev() {
                        OP_FROMALTSTACK { if *bit { 1 } else { 0 } } OP_EQUALVERIFY
                    }
                },
                witness.clone()
            ));
            assert!(
                execute_script_with_inputs(
                    script! {
                        { verify_hash_path_to_integer(8, commitment) }
                        { value } OP_EQUAL
                    },
                    witness
                )
                .success
            );
        }
    }

    #[test]
    fn retained_bits_preserve_order_and_unrelated_state() {
        let bits = [true, false, true, false, false];
        let preimage = [0x42; 32];
        let commitment = hash_path_commitment(&preimage, &bits);
        let mut witness = vec![vec![77]];
        witness.extend(
            bits.iter()
                .rev()
                .map(|bit| if *bit { vec![1] } else { vec![] }),
        );
        witness.push(preimage.to_vec());
        let result = crate::support::execution::execute_script_with_inputs_strict(
            script! {
                99 OP_TOALTSTACK
                { verify_hash_path_to_altstack(bits.len(), commitment) }
                OP_1 OP_EQUALVERIFY
                77 OP_EQUALVERIFY
                for bit in bits.iter().rev() {
                    OP_FROMALTSTACK { if *bit { 1 } else { 0 } } OP_EQUALVERIFY
                }
                OP_FROMALTSTACK 99 OP_EQUAL
            },
            witness,
        );
        assert!(result.success, "retained bit contract changed: {result}");
    }

    #[test]
    fn retained_bit_verifier_rejects_wrong_opening_and_malformed_input() {
        let preimage = [0x42; 32];
        let commitment = hash_path_commitment(&preimage, &[true, false, true]);
        let wrong = crate::support::execution::execute_script_with_inputs_strict(
            script! { { verify_hash_path_to_altstack(3, commitment) } },
            vec![vec![1], vec![], vec![1], vec![0x43; 32]],
        );
        assert!(matches!(
            wrong.error,
            Some(bitcoin_scriptexec::ExecError::EqualVerify)
        ));

        let malformed = crate::support::execution::execute_script_with_inputs_strict(
            script! { { verify_hash_path_to_altstack(1, commitment) } },
            vec![vec![2], preimage.to_vec()],
        );
        assert!(!malformed.success);

        let missing = crate::support::execution::execute_script_with_inputs_strict(
            script! { { verify_hash_path_to_altstack(1, commitment) } },
            vec![preimage.to_vec()],
        );
        assert!(matches!(
            missing.error,
            Some(bitcoin_scriptexec::ExecError::InvalidStackOperation)
        ));
    }

    #[test]
    #[should_panic(expected = "bit_width must be non-zero")]
    fn retained_bit_verifier_rejects_zero_width() {
        let _ = verify_hash_path_to_altstack(0, [0; 20]);
    }

    #[test]
    fn noncanonical_legacy_selectors_are_normalized_but_tapscript_rejects() {
        for (selector, bit) in [
            (vec![0], false),
            (vec![0x80], false),
            (vec![0, 0x80], false),
            (vec![2], true),
            (vec![0x81], true),
            (vec![1, 0], true),
            (vec![0, 1], true),
        ] {
            let preimage = vec![0x42; 32];
            let commitment = hash_path_commitment(&preimage, &[bit]);
            let witness = vec![selector, preimage];
            assert!(legacy_success(
                verify_hash_path(1, commitment),
                witness.clone()
            ));
            let script = script! {
                { verify_hash_path_to_altstack(1, commitment) }
                OP_FROMALTSTACK { if bit { 1 } else { 0 } } OP_EQUALVERIFY
            };
            assert!(legacy_success(script.clone(), witness.clone()));
            assert!(!execute_script_with_inputs(script, witness.clone()).success);
            assert!(legacy_success(
                script! {
                    { verify_hash_path_to_integer(1, commitment) }
                    { if bit { 1 } else { 0 } } OP_EQUAL
                },
                witness
            ));
        }
    }

    #[test]
    fn unbound_preimage_allows_first_bit_substitution() {
        let preimage = [0x42; 32];
        let substitute = sha256::Hash::hash(&preimage).to_byte_array();
        let commitment = hash_path_integer_commitment(&preimage, 43, 8);
        assert_eq!(commitment, hash_path_integer_commitment(&substitute, 42, 8));
        for (opening, value) in [(&preimage, 43), (&substitute, 42)] {
            assert!(legacy_success(
                script! {
                    { verify_hash_path_to_integer(8, commitment) } { value } OP_EQUAL
                },
                hash_path_integer_witness(opening, value, 8)
            ));
        }
    }

    #[test]
    fn hash_function_and_composition_contract() {
        let x = b"nonce";
        assert_eq!(
            hash_path_commitment(x, &[false]),
            ripemd160::Hash::hash(x).to_byte_array()
        );
        assert_eq!(
            hash_path_commitment(x, &[true]),
            ripemd160::Hash::hash(sha256::Hash::hash(x).as_byte_array()).to_byte_array()
        );
        let a = [true, false];
        let b = [false, true];
        assert_eq!(
            hash_path_commitment(&hash_path_commitment(x, &a), &b),
            hash_path_commitment(x, &[true, false, false, true])
        );
    }

    #[test]
    fn malformed_openings_and_integer_boundaries() {
        for value in [0, 0x7fff_ffff] {
            let commitment = hash_path_integer_commitment(b"", value, 31);
            let witness = hash_path_integer_witness(b"", value, 31);
            assert!(
                execute_script_with_inputs(
                    script! {
                        { verify_hash_path_to_integer(31, commitment) } { value } OP_EQUAL
                    },
                    witness
                )
                .success
            );
        }
        let commitment = hash_path_integer_commitment(b"nonce", 0, 1);
        assert!(
            !execute_script_with_inputs(verify_hash_path(1, commitment), vec![b"nonce".to_vec()])
                .success
        );
        let oversized = vec![42; 521];
        let commitment = hash_path_integer_commitment(&oversized, 0, 1);
        assert!(
            !crate::support::execution::execute_script(script! {
                OP_0 { oversized } { verify_hash_path(1, commitment) }
            })
            .success
        );
    }

    #[test]
    #[should_panic(expected = "bit_width must be non-zero")]
    fn empty_host_path_is_rejected() {
        hash_path_commitment(b"", &[]);
    }

    #[test]
    #[should_panic(expected = "bit_width must be non-zero")]
    fn empty_script_path_is_rejected() {
        hash_path_script(0);
    }

    #[test]
    #[should_panic(expected = "value does not fit")]
    fn oversized_integer_is_rejected() {
        hash_path_integer_witness(b"", 2, 1);
    }

    #[test]
    fn verifies_and_returns_integers() {
        for (value, width) in [(0, 1), (1, 1), (0x55, 7), (0x1234_5678, 31)] {
            let preimage = [0x42; 32];
            let commitment = hash_path_integer_commitment(&preimage, value, width);
            let witness = hash_path_integer_witness(&preimage, value, width);
            let result = execute_script_with_inputs(
                script! {
                    { verify_hash_path_to_integer(width, commitment) }
                    { value }
                    OP_EQUAL
                },
                witness,
            );
            assert!(result.success, "value={value}, width={width}: {result}");
        }
    }

    #[test]
    fn wrong_opening_fails() {
        let width = 8;
        let preimage = [0x11; 32];
        let commitment = hash_path_integer_commitment(&preimage, 42, width);
        let witness = hash_path_integer_witness(&preimage, 43, width);
        let result = execute_script_with_inputs(
            script! { { verify_hash_path_to_integer(width, commitment) } OP_DROP OP_1 },
            witness,
        );
        assert!(!result.success);
    }

    #[test]
    fn wrong_preimage_fails() {
        let width = 8;
        let commitment = hash_path_integer_commitment(&[0x11; 32], 42, width);
        let witness = hash_path_integer_witness(&[0x12; 32], 42, width);
        let result = execute_script_with_inputs(
            script! { { verify_hash_path_to_integer(width, commitment) } OP_DROP OP_1 },
            witness,
        );
        assert!(!result.success);
    }

    #[test]
    fn non_canonical_bit_fails() {
        let width = 1;
        let preimage = [0x23; 32];
        let commitment = hash_path_integer_commitment(&preimage, 1, width);
        let witness = vec![vec![2], preimage.to_vec()];
        let result = execute_script_with_inputs(
            script! { { verify_hash_path_to_integer(width, commitment) } OP_DROP OP_1 },
            witness,
        );
        assert!(!result.success);
    }

    #[test]
    fn generic_verifier_consumes_bits() {
        let bits = [true, false, true, true];
        let preimage = b"nonce";
        let commitment = hash_path_commitment(preimage, &bits);
        let mut witness = bits
            .iter()
            .rev()
            .map(|bit| if *bit { vec![1] } else { vec![] })
            .collect::<Vec<_>>();
        witness.push(preimage.to_vec());

        let result = execute_script_with_inputs(verify_hash_path(bits.len(), commitment), witness);
        assert!(result.success, "{result}");
        assert_eq!(result.final_stack.len(), 1);
    }

    #[test]
    fn digest_can_seed_a_later_path() {
        let alice_preimage = [0x42; 32];
        let alice_bits = [true, false, false, true];
        let bob_bits = [false, true, true];
        let alice_commitment = hash_path_commitment(&alice_preimage, &alice_bits);
        let bob_commitment = hash_path_commitment(&alice_commitment, &bob_bits);

        // Bob's bits are deepest. Alice's path consumes only Alice's opening,
        // leaving its digest directly above Bob's bit zero for the next path.
        let mut witness = bob_bits
            .iter()
            .rev()
            .chain(alice_bits.iter().rev())
            .map(|bit| if *bit { vec![1] } else { vec![] })
            .collect::<Vec<_>>();
        witness.push(alice_preimage.to_vec());

        let result = execute_script_with_inputs(
            verify_hash_path_chain(
                alice_bits.len(),
                alice_commitment,
                bob_bits.len(),
                bob_commitment,
            ),
            witness,
        );
        assert!(result.success, "{result}");
        assert_eq!(result.final_stack.len(), 1);
    }

    #[test]
    fn digest_chain_rejects_a_wrong_intermediate_checkpoint() {
        let alice_preimage = [0x42; 32];
        let alice_bits = [true, false, false, true];
        let bob_bits = [false, true, true];
        let alice_commitment = hash_path_commitment(&alice_preimage, &alice_bits);
        let bob_commitment = hash_path_commitment(&alice_commitment, &bob_bits);
        let mut witness = bob_bits
            .iter()
            .rev()
            .chain(alice_bits.iter().rev())
            .map(|bit| if *bit { vec![1] } else { vec![] })
            .collect::<Vec<_>>();
        witness.push(alice_preimage.to_vec());

        let result = execute_script_with_inputs(
            verify_hash_path_chain(4, [0x99; 20], 3, bob_commitment),
            witness,
        );
        assert!(
            !result.success,
            "accepted a detached intermediate checkpoint"
        );
    }

    #[test]
    #[should_panic(expected = "bit_width must be in 1..=31")]
    fn integer_width_above_scriptnum_limit_panics() {
        let _ = hash_path_integer_commitment(b"nonce", 0, 32);
    }
}
