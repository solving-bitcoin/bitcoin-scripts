//! Multi-digit Lamport commitments over radix `2^w` digits.
//!
//! Each digit has `radix` public HASH160 images. Opening digit value `v` reveals
//! the preimage of image `v`; the digit value is left on the stack in order.
//! Digit width trades script bytes (images) against witness bytes (preimages).
//! Unlike [`super::lamport::lamport_2bit_commit`], an out-of-range value is
//! rejected instead of clamped.

use crate::{signatures::lamport::hash160_bytes, support::script::*};

/// Deterministic secret for digit `digit` and value `value` under `seed`.
pub fn lamport_digit_secret(seed: &[u8], digit: u32, value: u32) -> Vec<u8> {
    let mut input = seed.to_vec();
    input.extend_from_slice(&digit.to_be_bytes());
    input.extend_from_slice(&value.to_be_bytes());
    // 16-byte secrets, as in the Winternitz comparison tables.
    {
        use bitcoin::hashes::Hash;
        bitcoin::hashes::sha256::Hash::hash(&input).to_byte_array()[..16].to_vec()
    }
}

/// Public images `images[digit][value] = HASH160(secret(digit, value))`.
pub fn lamport_digit_images(seed: &[u8], digits: u32, radix: u32) -> Vec<Vec<[u8; 20]>> {
    (0..digits)
        .map(|digit| {
            (0..radix)
                .map(|value| hash160_bytes(&lamport_digit_secret(seed, digit, value)))
                .collect()
        })
        .collect()
}

/// Open `images.len()` digits.
///
/// Before (witness, bottom to top): for digit `0` first, then digit `1`, ...,
/// the pair `value, preimage`. After: `v[0] ... v[digits-1]`, last digit on top.
/// A value outside `0..radix` or a wrong preimage aborts. No hints.
pub fn lamport_digits_commit(images: &[Vec<[u8; 20]>]) -> Script {
    assert!(!images.is_empty(), "at least one digit");
    let radix = images[0].len() as u32;
    assert!(radix >= 2, "radix at least two");
    assert!(images.iter().all(|d| d.len() as u32 == radix));
    script! {
        // Digit d-1 is on top of the witness; park each opened value on the altstack.
        for digit in images.iter().rev() {
            OP_TOALTSTACK
            OP_DUP 0 { radix } OP_WITHIN OP_VERIFY
            OP_DUP OP_TOALTSTACK
            for image in digit.iter().rev() { { image.to_vec() } }
            OP_FROMALTSTACK OP_ROLL
            OP_FROMALTSTACK OP_HASH160 OP_EQUALVERIFY
            for _ in 0..(radix - 1) / 2 { OP_2DROP }
            if (radix - 1) % 2 == 1 { OP_DROP }
            OP_TOALTSTACK
        }
        for _ in 0..images.len() { OP_FROMALTSTACK }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::execution::execute_raw_script_with_inputs_strict;
    use bitcoin_scriptexec::ExecError;

    const SEED: &[u8] = b"lamport-digits-test";

    fn num(value: i64) -> Vec<u8> {
        let mut bytes = [0u8; 8];
        let len = bitcoin::script::write_scriptint(&mut bytes, value);
        bytes[..len].to_vec()
    }

    /// Witness for the given digit values, bottom to top.
    fn witness(values: &[u32], radix_for_secrets: u32) -> Vec<Vec<u8>> {
        let _ = radix_for_secrets;
        values
            .iter()
            .enumerate()
            .flat_map(|(digit, &v)| {
                [
                    num(i64::from(v)),
                    lamport_digit_secret(SEED, digit as u32, v),
                ]
            })
            .collect()
    }

    /// Compile with a terminal check that the opened values equal `values`.
    fn leaf(images: &[Vec<[u8; 20]>], values: &[u32]) -> Vec<u8> {
        script! {
            { lamport_digits_commit(images) }
            for &v in values.iter().rev() { { i64::from(v) } OP_EQUALVERIFY }
            OP_TRUE
        }
        .compile_with_policy()
        .to_bytes()
    }

    fn run(compiled: &[u8], witness: Vec<Vec<u8>>) -> Option<bool> {
        let result = execute_raw_script_with_inputs_strict(compiled.to_vec(), witness);
        if result.error.is_some() {
            None
        } else {
            Some(result.success)
        }
    }

    #[test]
    fn opens_every_value_combination_in_order() {
        for (digits, radix) in [(1u32, 2u32), (3, 2), (1, 4), (2, 4), (1, 16), (2, 16)] {
            let images = lamport_digit_images(SEED, digits, radix);
            let total = radix.pow(digits);
            for code in 0..total {
                let values: Vec<u32> = (0..digits)
                    .map(|d| (code / radix.pow(digits - 1 - d)) % radix)
                    .collect();
                let compiled = leaf(&images, &values);
                assert_eq!(
                    run(&compiled, witness(&values, radix)),
                    Some(true),
                    "digits {digits} radix {radix} values {values:?}"
                );
            }
        }
    }

    #[test]
    fn rejects_wrong_preimages_swapped_digits_and_value_mismatch() {
        let images = lamport_digit_images(SEED, 2, 4);
        let compiled = leaf(&images, &[1, 2]);
        assert_eq!(run(&compiled, witness(&[1, 2], 4)), Some(true));
        // Preimage belongs to another value of the same digit.
        let mut forged = witness(&[1, 2], 4);
        forged[1] = lamport_digit_secret(SEED, 0, 3);
        assert_eq!(run(&compiled, forged), None);
        // Claimed value differs from the value whose preimage is revealed.
        let mut forged = witness(&[1, 2], 4);
        forged[0] = num(2);
        assert_eq!(run(&compiled, forged), None);
        // Digit positions swapped.
        let mut forged = witness(&[1, 2], 4);
        forged.swap(1, 3);
        assert_eq!(run(&compiled, forged), None);
        // An arbitrary short preimage.
        let mut forged = witness(&[1, 2], 4);
        forged[3] = b"nope".to_vec();
        assert_eq!(run(&compiled, forged), None);
    }

    #[test]
    fn rejects_out_of_range_values_instead_of_clamping() {
        let images = lamport_digit_images(SEED, 1, 4);
        let compiled = script! { { lamport_digits_commit(&images) } OP_DROP OP_TRUE }
            .compile_with_policy()
            .to_bytes();
        for bad in [-1i64, 4, 7, 255] {
            let witness = vec![num(bad), lamport_digit_secret(SEED, 0, 3)];
            let result = execute_raw_script_with_inputs_strict(compiled.clone(), witness);
            assert_eq!(result.error, Some(ExecError::Verify), "value {bad}");
        }
    }

    #[test]
    fn recorded_sizes_are_current() {
        // (message bits, digit width, script bytes)
        for (bits, width, bytes) in [
            (8u32, 1u32, 463usize),
            (8, 2, 403),
            (8, 3, 560),
            (8, 4, 717),
            (16, 2, 807),
            (32, 1, 1_855),
            (32, 2, 1_615),
            (32, 3, 2_056),
            (32, 4, 2_871),
            (160, 2, 8_079),
        ] {
            let digits = bits.div_ceil(width);
            let images = lamport_digit_images(SEED, digits, 1 << width);
            let size = script! { { lamport_digits_commit(&images) } }
                .compile_with_policy()
                .len();
            assert_eq!(size, bytes, "{bits} bits at width {width}");
        }
    }
}
