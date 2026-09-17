use super::stack::u4_drop;
use crate::support::script::*;

/// Pushes the 16x16 table for multiplication modulo 16.
pub fn u4_push_full_product_table() -> Script {
    script! {
        for a in (0..16).rev() {
            for b in (0..16).rev() {
                { (a * b) % 16 }
            }
        }
    }
}

/// Drops a full modulo-16 product table.
pub fn u4_drop_full_product_table() -> Script {
    u4_drop(256)
}

/// Multiplies two canonical u4 values modulo 16.
///
/// The product table must be below the two inputs. The table remains below the
/// result so callers can reuse it or remove it with `u4_drop_full_product_table`.
pub fn u4_mul_mod16() -> Script {
    script! {
        // Both witness values must be valid table coordinates.
        OP_DUP 0 16 OP_WITHIN OP_VERIFY
        1 OP_PICK 0 16 OP_WITHIN OP_VERIFY

        // Form 16*a+b, with a below b on entry.
        OP_SWAP
        OP_DUP
        OP_ADD
        OP_ADD
        OP_ADD
        OP_ADD
        OP_SWAP
        OP_ADD
        OP_PICK
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arithmetic::test_helpers::run_with_witness;
    use crate::support::execution::{execute_raw_script_with_inputs_strict, execute_script};

    fn multiplication_script() -> Vec<u8> {
        script! {
            OP_TOALTSTACK
            OP_TOALTSTACK
            { u4_push_full_product_table() }
            OP_FROMALTSTACK
            OP_FROMALTSTACK
            { u4_mul_mod16() }
            OP_TOALTSTACK
            { u4_drop_full_product_table() }
            OP_FROMALTSTACK
            OP_EQUAL
        }
        .compile_with_policy()
        .to_bytes()
    }

    #[test]
    fn multiplies_every_nibble_pair() {
        let script = multiplication_script();
        for a in 0..16 {
            for b in 0..16 {
                run_with_witness(&script, [(a * b) % 16, a, b]);
            }
        }
    }

    #[test]
    fn rejects_out_of_range_nibbles() {
        let script = multiplication_script();
        for &(a, b) in &[(-1, 0), (16, 0), (0, -1), (0, 16)] {
            let witness = [0, a, b]
                .into_iter()
                .map(|value| {
                    let mut bytes = [0u8; 8];
                    let len = bitcoin::script::write_scriptint(&mut bytes, i64::from(value));
                    bytes[..len].to_vec()
                })
                .collect();
            let result = execute_raw_script_with_inputs_strict(script.clone(), witness);
            assert!(
                !result.success,
                "accepted invalid pair ({a}, {b}): {result}"
            );
        }
    }

    #[test]
    fn preserves_surrounding_main_and_alt_stack_items() {
        let result = execute_script(script! {
            OP_9 OP_TOALTSTACK
            7
            0
            3
            5
            OP_TOALTSTACK
            OP_TOALTSTACK
            { u4_push_full_product_table() }
            OP_FROMALTSTACK
            OP_FROMALTSTACK
            { u4_mul_mod16() }
            OP_TOALTSTACK
            { u4_drop_full_product_table() }
            OP_FROMALTSTACK
            OP_EQUALVERIFY
            7 OP_EQUALVERIFY
            OP_FROMALTSTACK 9 OP_EQUALVERIFY
            OP_TRUE
        });
        assert!(
            result.success,
            "u4 multiplication changed surrounding state: {result}"
        );
    }
}
