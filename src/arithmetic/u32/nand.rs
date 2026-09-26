use crate::arithmetic::u32::{and::u8_and, zip::u32_copy_zip};
use crate::support::script::*;

/// Bitwise NAND of two byte limbs using the shared u8 Boolean table.
pub fn u8_nand(i: u32) -> Script {
    script! {
        { u8_and(i) }
        255
        OP_SWAP
        OP_SUB
    }
}

/// Bitwise NAND of two u32 values, preserving the value selected by `a`.
///
/// The shared XOR/AND/OR table must be below the working words. `stack_size`
/// is one plus the number of u32 words above that table.
pub fn u32_nand(a: u32, b: u32, stack_size: u32) -> Script {
    assert_ne!(a, b);
    assert!(stack_size >= 2);
    script! {
        { u32_copy_zip(a, b) }

        { u8_nand(8 + (stack_size - 2) * 4) }
        OP_TOALTSTACK

        { u8_nand(6 + (stack_size - 2) * 4) }
        OP_TOALTSTACK

        { u8_nand(4 + (stack_size - 2) * 4) }
        OP_TOALTSTACK

        { u8_nand(2 + (stack_size - 2) * 4) }

        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_FROMALTSTACK
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arithmetic::test_helpers::{run_with_witness, word_witness};
    use crate::arithmetic::u32::stack::{
        u32_drop, u32_equal, u32_equalverify, u32_fromaltstack, u32_push, u32_toaltstack,
    };
    use crate::arithmetic::u32::xor::{u8_drop_xor_table, u8_push_xor_table};
    use crate::support::execution::{execute_raw_script_with_inputs_strict, execute_script};
    use rand::{rngs::StdRng, Rng, SeedableRng};

    fn nand_script() -> Vec<u8> {
        script! {
            { u32_toaltstack() }
            { u32_toaltstack() }
            { u8_push_xor_table() }
            { u32_fromaltstack() }
            { u32_fromaltstack() }
            { u32_nand(0, 1, 3) }
            { u32_toaltstack() }
            { u32_drop() }
            { u8_drop_xor_table() }
            { u32_fromaltstack() }
            { u32_equal() }
        }
        .compile_with_policy()
        .to_bytes()
    }

    #[test]
    fn nand_matches_host_boundaries_and_patterns() {
        let script = nand_script();
        for &(x, y) in &[
            (0, 0),
            (0, u32::MAX),
            (u32::MAX, u32::MAX),
            (0x0123_4567, 0x89ab_cdef),
            (0x8000_0000, 0x7fff_ffff),
        ] {
            run_with_witness(
                &script,
                word_witness(!(x & y))
                    .chain(word_witness(x))
                    .chain(word_witness(y)),
            );
        }

        let mut rng = StdRng::seed_from_u64(0x7533_325f_6e61_6e64);
        for _ in 0..100 {
            let x: u32 = rng.gen();
            let y: u32 = rng.gen();
            run_with_witness(
                &script,
                word_witness(!(x & y))
                    .chain(word_witness(x))
                    .chain(word_witness(y)),
            );
        }
    }

    #[test]
    fn rejects_out_of_range_byte_witnesses() {
        let script = nand_script();
        let encode = |value: i64| {
            let mut bytes = [0u8; 8];
            let len = bitcoin::script::write_scriptint(&mut bytes, value);
            bytes[..len].to_vec()
        };
        for invalid in [-1, 256] {
            let mut witness = vec![encode(0); 12];
            witness[4] = encode(invalid);
            let result = execute_raw_script_with_inputs_strict(script.clone(), witness);
            assert!(!result.success, "accepted invalid byte {invalid}: {result}");
        }
    }

    #[test]
    fn preserves_surrounding_main_and_alt_stack_items() {
        let result = execute_script(script! {
            OP_9 OP_TOALTSTACK
            7
            { u32_push(0x1234_5678) }
            { u32_push(0xdead_beef) }
            { u32_toaltstack() }
            { u32_toaltstack() }
            { u8_push_xor_table() }
            { u32_fromaltstack() }
            { u32_fromaltstack() }
            { u32_nand(0, 1, 3) }
            { u32_toaltstack() }
            { u32_drop() }
            { u8_drop_xor_table() }
            { u32_fromaltstack() }
            { u32_push(!(0x1234_5678 & 0xdead_beef)) }
            { u32_equalverify() }
            7 OP_EQUALVERIFY
            OP_FROMALTSTACK 9 OP_EQUALVERIFY
            OP_TRUE
        });
        assert!(result.success, "NAND changed surrounding state: {result}");
    }
}
