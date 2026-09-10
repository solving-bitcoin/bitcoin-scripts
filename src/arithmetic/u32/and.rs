use crate::arithmetic::u32::zip::u32_copy_zip;
use crate::support::script::*;

/// Bitwise AND of two u8 elements, i denoting how many values are there in the stack after the table (including the input numbers A and B)
/// Expects the u8_xor_table on the stack and uses it to process even and odd bits separately
pub fn u8_and(i: u32) -> Script {
    script! {
        // f_A = f(A)
        OP_DUP
        {i}
        OP_ADD
        OP_PICK

        // A_even = f_A << 1
        OP_DUP
        OP_DUP
        OP_ADD

        // A_odd = A - A_even
        OP_ROT
        OP_SWAP
        OP_SUB

        // f_B = f(B)
        OP_ROT
        OP_DUP
        {i + 1}
        OP_ADD
        OP_PICK

        // B_even = f_B << 1
        OP_DUP
        OP_DUP
        OP_ADD

        // B_odd = B - B_even
        OP_ROT
        OP_SWAP
        OP_SUB

        // A_andxor_B_even = f_A + f_B
        OP_SWAP
        3
        OP_ROLL
        OP_ADD
        // A_and_B_even = f(A_andxor_B_even)
        {i}
        OP_ADD
        OP_PICK

        // A_andxor_B_odd = A_odd + B_odd
        OP_SWAP
        OP_ROT
        OP_ADD

        // A_and_B_odd = f(A_andxor_B_odd)
        {i - 1}
        OP_ADD
        OP_PICK

        // A_and_B = A_and_B_odd + (A_and_B_even << 1)
        OP_OVER
        OP_ADD
        OP_ADD
    }
}

/// Bitwise AND of a-th and b-th u32 elements from the top, keeps a-th element in the stack
/// Expects u8_xor_table on the stack to use u8_and, and stack_size as a parameter to locate the table (which should be equal to 1 + number of the u32 elements in the stack after the table)
pub fn u32_and(a: u32, b: u32, stack_size: u32) -> Script {
    assert_ne!(a, b);
    script! {
        {u32_copy_zip(a, b)}

        {u8_and(8 + (stack_size - 2) * 4)}

        OP_TOALTSTACK

        {u8_and(6 + (stack_size - 2) * 4)}

        OP_TOALTSTACK

        {u8_and(4 + (stack_size - 2) * 4)}

        OP_TOALTSTACK

        {u8_and(2 + (stack_size - 2) * 4)}

        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_FROMALTSTACK
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arithmetic::test_helpers::{run_with_witness, word_witness};
    use crate::arithmetic::u32::stack::*;
    use crate::arithmetic::u32::xor::{u8_drop_xor_table, u8_push_xor_table};
    use rand::{rngs::StdRng, Rng, SeedableRng};

    #[test]
    fn test_and() {
        println!("u32 and: {} bytes", u32_and(0, 1, 3).len());
        let script = script! {
            { u32_toaltstack() }
            { u32_toaltstack() }
            { u8_push_xor_table() }
            { u32_fromaltstack() }
            { u32_fromaltstack() }
            { u32_and(0, 1, 3) }
            { u32_toaltstack() }
            { u32_drop() } // drop the preserved y
            { u8_drop_xor_table() }
            { u32_fromaltstack() }
            { u32_equal() }
        }
        .compile_with_policy()
        .to_bytes();
        let mut rng = StdRng::seed_from_u64(0x7533325f616e64);
        for _ in 0..100 {
            let x: u32 = rng.gen();
            let y: u32 = rng.gen();
            run_with_witness(
                &script,
                word_witness(x & y)
                    .chain(word_witness(x))
                    .chain(word_witness(y)),
            );
        }
    }
    #[test]
    fn test_u8_and_exhaustive() {
        // Keep the expected byte below the table and restore the two operands
        // above it. Only witness values vary across the exhaustive domain.
        let script = script! {
            OP_TOALTSTACK OP_TOALTSTACK
            { u8_push_xor_table() }
            OP_FROMALTSTACK OP_FROMALTSTACK
            { u8_and(2) }
            OP_TOALTSTACK
            { u8_drop_xor_table() }
            OP_FROMALTSTACK
            OP_EQUAL
        }
        .compile_with_policy()
        .to_bytes();
        for a in 0..256 {
            for b in 0..256 {
                run_with_witness(&script, [a & b, a, b]);
            }
        }
    }
}
