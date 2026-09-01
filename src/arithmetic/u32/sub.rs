use crate::treepp::*;
use crate::u32::u32_zip::{u32_copy_zip, u32_zip};

/// Subtracts the top two byte limbs, normalizes the difference modulo 256,
/// and leaves the borrow bit on top of the normalized byte.
pub fn u8_sub_borrow() -> Script {
    script! {
        OP_SUB
        OP_DUP
        0
        OP_LESSTHAN
        OP_IF
            256
            OP_ADD
            1
        OP_ELSE
            0
        OP_ENDIF
    }
}

/// Subtracts the top two byte limbs and normalizes the result modulo 256.
pub fn u8_sub() -> Script {
    script! {
        OP_SUB
        OP_DUP
        0
        OP_LESSTHAN
        OP_IF
            256
            OP_ADD
        OP_ENDIF
    }
}

fn u32_sub_zipped(reverse_operands: bool) -> Script {
    script! {
        if reverse_operands {
            OP_SWAP
        }
        u8_sub_borrow
        OP_SWAP
        OP_TOALTSTACK

        if reverse_operands {
            OP_ROT
        }
        OP_ADD
        u8_sub_borrow
        OP_SWAP
        OP_TOALTSTACK

        if reverse_operands {
            OP_ROT
        }
        OP_ADD
        u8_sub_borrow
        OP_SWAP
        OP_TOALTSTACK

        if reverse_operands {
            OP_ROT
        }
        OP_ADD
        u8_sub

        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_FROMALTSTACK
    }
}

/// Wrapping subtraction of the `b`th u32 from the `a`th u32, preserving `a`.
pub fn u32_sub(a: u32, b: u32) -> Script {
    assert_ne!(a, b);
    script! {
        { u32_copy_zip(a, b) }
        { u32_sub_zipped(a > b) }
    }
}

/// Wrapping subtraction of the `b`th u32 from the `a`th u32, consuming both.
pub fn u32_sub_drop(a: u32, b: u32) -> Script {
    assert_ne!(a, b);
    script! {
        { u32_zip(a, b) }
        { u32_sub_zipped(a > b) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::u32::u32_std::{u32_equal, u32_equalverify, u32_push};
    use rand::Rng;

    #[test]
    fn test_u8_sub_exhaustive() {
        for a in 0i32..256 {
            for b in 0i32..256 {
                let expected = (a - b).rem_euclid(256);
                let script_without_borrow = script! {
                    { a }
                    { b }
                    { u8_sub() }
                    { expected }
                    OP_EQUAL
                };
                let script_with_borrow = script! {
                    { a }
                    { b }
                    { u8_sub_borrow() }
                    { (a < b) as u32 }
                    OP_EQUAL
                    OP_TOALTSTACK
                    { expected }
                    OP_EQUAL
                    OP_FROMALTSTACK
                    OP_BOOLAND
                };
                run(script_without_borrow);
                run(script_with_borrow);
            }
        }
    }

    #[test]
    fn test_u32_sub_boundaries_and_random_values() {
        let boundaries = [
            0,
            1,
            0xff,
            0x100,
            0x7fff_ffff,
            0x8000_0000,
            0xffff_fffe,
            u32::MAX,
        ];

        for &a in &boundaries {
            for &b in &boundaries {
                check_sub(a, b);
            }
        }

        let mut rng = rand::thread_rng();
        for _ in 0..1_000 {
            check_sub(rng.gen(), rng.gen());
        }
    }

    fn check_sub(a: u32, b: u32) {
        let expected = a.wrapping_sub(b);
        let top_first_drop_script = script! {
            { u32_push(b) }
            { u32_push(a) }
            { u32_sub_drop(0, 1) }
            { u32_push(expected) }
            { u32_equal() }
        };
        let top_first_preserving_script = script! {
            { u32_push(b) }
            { u32_push(a) }
            { u32_sub(0, 1) }
            { u32_push(expected) }
            { u32_equalverify() }
            { u32_push(a) }
            { u32_equal() }
        };
        let deeper_first_drop_script = script! {
            { u32_push(a) }
            { u32_push(b) }
            { u32_sub_drop(1, 0) }
            { u32_push(expected) }
            { u32_equal() }
        };
        let deeper_first_preserving_script = script! {
            { u32_push(a) }
            { u32_push(b) }
            { u32_sub(1, 0) }
            { u32_push(expected) }
            { u32_equalverify() }
            { u32_push(a) }
            { u32_equal() }
        };

        run(top_first_drop_script);
        run(top_first_preserving_script);
        run(deeper_first_drop_script);
        run(deeper_first_preserving_script);
    }
}
