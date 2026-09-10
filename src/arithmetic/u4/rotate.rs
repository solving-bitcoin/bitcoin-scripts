use crate::arithmetic::u4::shift::*;
use crate::support::script::*;

/// Push 2 nib right shift tables, i.e. tables to calculate (16 * Y + X) >> n modulo 16 (which is equal to concatenating two nibbles and shifting them by n)
pub fn u4_push_rrot_tables() -> Script {
    script! {
       {  u4_push_2_nib_rshift_tables() }
    }
}

/// Drop 2 nib right shift tables
pub fn u4_drop_rrot_tables() -> Script {
    script! {
        { u4_drop_2_nib_rshift_tables() }
    }
}

/// This part changes the order of the nibbles, i.e. it makes the shift/4 part of the operation
/// It also pushes 0's instead of picking if the operation is shifting, and pushes the extra starting element accordingly for the u4_rrot functions
pub fn u4_prepare_number(shift: u32, number_pos: u32, is_shift: bool) -> Script {
    let pos_shift = shift / 4;
    let pos_shift_extra = pos_shift + 1;
    script! {
        for _ in (8 - pos_shift_extra)..8 {
            if is_shift {
                OP_0
            } else {
                { number_pos + 7 - (8 - pos_shift_extra) }
                OP_PICK
            }
        }
        for _ in 0..(8 - pos_shift) {
            { number_pos + 7 + pos_shift_extra }
            OP_PICK
        }
    }
}

/// This part changes the values of the nibbles, i.e. it makes the shift%4 part of the operation
/// number_pos is equal to the number of elements after the number in stack
pub fn u4_rrot(shift: u32, number_pos: u32, shift_tables: u32, is_shift: bool) -> Script {
    let bit_shift = shift % 4;
    script! {
        { u4_prepare_number(shift, number_pos, is_shift) }
        if bit_shift == 0 {
            for _ in 0..8 {
                OP_TOALTSTACK
            }
            OP_DROP
        } else {
            for i in 0..8 {
                if i == 7 {
                    OP_SWAP
                    { u4_2_nib_rshift_n(bit_shift, shift_tables - 2 + (9 - i)) }
                } else {
                    OP_OVER
                    { u4_2_nib_rshift_n(bit_shift, shift_tables - 2 + (10 - i)) }
                }
                OP_TOALTSTACK
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arithmetic::test_helpers::{nibble_witness, run_with_witness};
    use crate::arithmetic::u4::stack::{
        u4_drop, u4_fromaltstack, u4_toaltstack, u4_u32_verify_from_altstack,
    };
    use rand::{rngs::StdRng, Rng, SeedableRng};

    fn rrot(x: u32, n: u32) -> u32 {
        if n == 0 {
            return x;
        }
        (x >> n) | (x << (32 - n))
    }

    fn rshift(x: u32, n: u32) -> u32 {
        if n == 0 {
            return x;
        }
        x >> n
    }

    fn check_rotations(is_shift: bool, expected: fn(u32, u32) -> u32, seed: u64) {
        // Witness: expected nibbles followed by input nibbles. Table setup,
        // operand preservation/cleanup, and every output check still execute.
        let scripts: Vec<_> = (1..31)
            .map(|n| {
                script! {
                    { u4_toaltstack(8) }
                    { u4_push_rrot_tables() }
                    { u4_fromaltstack(8) }
                    { u4_rrot(n, 0, 8, is_shift) }
                    { u4_drop(8) }
                    { u4_drop_rrot_tables() }
                    { u4_u32_verify_from_altstack() }
                    OP_TRUE
                }
                .compile_with_policy()
                .to_bytes()
            })
            .collect();
        let mut rng = StdRng::seed_from_u64(seed);
        for _ in 0..1000 {
            let x: u32 = rng.gen();
            for (i, script) in scripts.iter().enumerate() {
                let n = i as u32 + 1;
                run_with_witness(
                    script,
                    nibble_witness(expected(x, n)).chain(nibble_witness(x)),
                );
            }
        }
    }

    #[test]
    fn test_rrot() {
        check_rotations(false, rrot, 0x75345f726f74);
    }

    #[test]
    fn test_rshift() {
        check_rotations(true, rshift, 0x75345f7368696674);
    }
}
