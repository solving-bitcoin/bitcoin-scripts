use crate::arithmetic::u32::zip::u32_copy_zip;
use crate::support::script::*;

/// Bitwise OR of the top two byte limbs.
///
/// `i` is the number of stack items above the shared u8 logic table, including
/// the two inputs. The table is the same one used by u32 XOR and AND.
pub fn u8_or(i: u32) -> Script {
    script! {
        // f_A = f(A), A_even = f_A << 1, A_odd = A - A_even
        OP_DUP
        { i }
        OP_ADD
        OP_PICK
        OP_DUP
        OP_DUP
        OP_ADD
        OP_ROT
        OP_SWAP
        OP_SUB

        // f_B = f(B), B_even = f_B << 1, B_odd = B - B_even
        OP_ROT
        OP_DUP
        { i + 1 }
        OP_ADD
        OP_PICK
        OP_DUP
        OP_DUP
        OP_ADD
        OP_ROT
        OP_SWAP
        OP_SUB

        // OR the even bits through the shared lookup table.
        OP_SWAP
        3
        OP_ROLL
        OP_ADD
        OP_DUP
        OP_DUP
        OP_ADD
        OP_DUP
        255
        OP_GREATERTHAN
        OP_IF
            256
            OP_SUB
        OP_ENDIF
        { i + 1 }
        OP_ADD
        OP_PICK
        OP_SWAP
        { i + 1 }
        OP_ADD
        OP_PICK
        OP_ADD

        // OR the odd bits through the shared lookup table.
        OP_SWAP
        OP_ROT
        OP_ADD
        OP_DUP
        OP_DUP
        OP_ADD
        OP_DUP
        255
        OP_GREATERTHAN
        OP_IF
            256
            OP_SUB
        OP_ENDIF
        { i }
        OP_ADD
        OP_PICK
        OP_SWAP
        { i }
        OP_ADD
        OP_PICK
        OP_ADD

        // A_or_B = A_or_B_odd + (A_or_B_even << 1)
        OP_SWAP
        OP_DUP
        OP_ADD
        OP_ADD
    }
}

/// Bitwise OR of the `a`th and `b`th u32 values, preserving `a`.
///
/// Expects the shared u8 logic table below the working words. `stack_size` is
/// one plus the number of u32 words above that table.
pub fn u32_or(a: u32, b: u32, stack_size: u32) -> Script {
    assert_ne!(a, b);
    assert!(stack_size >= 2);
    script! {
        { u32_copy_zip(a, b) }

        { u8_or(8 + (stack_size - 2) * 4) }
        OP_TOALTSTACK

        { u8_or(6 + (stack_size - 2) * 4) }
        OP_TOALTSTACK

        { u8_or(4 + (stack_size - 2) * 4) }
        OP_TOALTSTACK

        { u8_or(2 + (stack_size - 2) * 4) }

        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_FROMALTSTACK
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arithmetic::u32::stack::{u32_drop, u32_equal, u32_push};
    use crate::arithmetic::u32::xor::{u8_drop_xor_table, u8_push_xor_table};
    use crate::support::execution::run;
    use rand::Rng;

    #[test]
    fn test_u8_or_exhaustive() {
        for a in 0..256 {
            for b in 0..256 {
                let script = script! {
                    { u8_push_xor_table() }
                    { a }
                    { b }
                    { u8_or(2) }
                    { a | b }
                    OP_EQUAL
                    OP_TOALTSTACK
                    { u8_drop_xor_table() }
                    OP_FROMALTSTACK
                };
                run(script);
            }
        }
    }

    #[test]
    fn test_u32_or() {
        let mut rng = rand::thread_rng();
        for _ in 0..100 {
            let a = rng.gen::<u32>();
            let b = rng.gen::<u32>();
            let script = script! {
                { u8_push_xor_table() }
                { u32_push(a) }
                { u32_push(b) }
                { u32_or(0, 1, 3) }
                { u32_push(a | b) }
                { u32_equal() }
                OP_TOALTSTACK
                { u32_drop() }
                { u8_drop_xor_table() }
                OP_FROMALTSTACK
            };
            run(script);
        }
    }
}
