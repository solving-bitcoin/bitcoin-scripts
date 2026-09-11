use crate::support::script::*;

fn u32_cmp(comparison: Script) -> Script {
    script! {
        4
        OP_ROLL
        OP_SWAP
        { comparison.clone() }
        OP_SWAP

        4
        OP_ROLL
        OP_2DUP
        OP_EQUAL
        3
        OP_ROLL
        OP_BOOLAND
        OP_SWAP
        OP_ROT
        { comparison.clone() }
        OP_BOOLOR
        OP_SWAP

        3
        OP_ROLL
        OP_2DUP
        OP_EQUAL
        3
        OP_ROLL
        OP_BOOLAND
        OP_SWAP
        OP_ROT
        { comparison.clone() }
        OP_BOOLOR
        OP_SWAP

        OP_ROT
        OP_2DUP
        OP_EQUAL
        3
        OP_ROLL
        OP_BOOLAND
        OP_SWAP
        OP_ROT
        { comparison }
        OP_BOOLOR
    }
}

fn u32_cmp_or_equal(comparison: Script) -> Script {
    script! {
        OP_2OVER
        OP_2OVER
        8
        OP_PICK
        OP_EQUAL
        OP_SWAP
        9
        OP_PICK
        OP_EQUAL
        OP_BOOLAND
        OP_SWAP
        9
        OP_PICK
        OP_EQUAL
        OP_BOOLAND
        OP_SWAP
        9
        OP_PICK
        OP_EQUAL
        OP_BOOLAND
        OP_TOALTSTACK
        { u32_cmp(comparison) }
        OP_FROMALTSTACK
        OP_BOOLOR
    }
}

/// Unsigned less-than comparison of the top two u32 values.
pub fn u32_lessthan() -> Script {
    u32_cmp(script! { OP_LESSTHAN })
}

/// Signed two's-complement less-than comparison of the top two u32 values.
///
/// The four byte limbs must already be canonical values in `0..=255`. The
/// words are interpreted as i32 values without changing their stack encoding.
pub fn u32_signed_lessthan() -> Script {
    script! {
        // Save the sign bit of the lower (left) word, then the top (right) word.
        7 OP_PICK
        128 OP_GREATERTHANOREQUAL
        OP_TOALTSTACK
        3 OP_PICK
        128 OP_GREATERTHANOREQUAL
        OP_TOALTSTACK

        { u32_lessthan() }
        OP_TOALTSTACK
        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_FROMALTSTACK

        // Different signs decide the result; equal signs use unsigned order.
        OP_SWAP
        OP_2DUP
        OP_EQUAL
        OP_NOT
        OP_IF
            OP_DROP
            OP_SWAP
            OP_DROP
        OP_ELSE
            OP_2DROP
        OP_ENDIF
    }
}

/// Unsigned greater-than comparison of the top two u32 values.
pub fn u32_greaterthan() -> Script {
    u32_cmp(script! { OP_GREATERTHAN })
}

/// Unsigned less-than-or-equal comparison of the top two u32 values.
pub fn u32_lessthanorequal() -> Script {
    u32_cmp_or_equal(script! { OP_LESSTHAN })
}

/// Unsigned greater-than-or-equal comparison of the top two u32 values.
pub fn u32_greaterthanorequal() -> Script {
    u32_cmp_or_equal(script! { OP_GREATERTHAN })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arithmetic::u32::stack::u32_push;
    use crate::support::execution::run;
    use rand::Rng;

    #[test]
    fn test_u32_comparisons() {
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
                check_comparisons(a, b);
            }
        }

        let mut rng = rand::thread_rng();
        for _ in 0..256 {
            check_comparisons(rng.gen(), rng.gen());
        }
    }

    #[test]
    fn test_u32_signed_less_than() {
        let boundaries = [0, 1, 0x7fff_ffff, 0x8000_0000, 0x8000_0001, 0xffff_ffff];

        for &a in &boundaries {
            for &b in &boundaries {
                check_signed_less_than(a, b);
            }
        }

        let mut rng = rand::thread_rng();
        for _ in 0..256 {
            check_signed_less_than(rng.gen(), rng.gen());
        }
    }

    fn check_signed_less_than(a: u32, b: u32) {
        let script = script! {
            { u32_push(a) }
            { u32_push(b) }
            { u32_signed_lessthan() }
            { ((a as i32) < (b as i32)) as u32 }
            OP_EQUAL
        };
        run(script);
    }

    fn check_comparisons(a: u32, b: u32) {
        let cases = [
            (u32_lessthan(), a < b),
            (u32_greaterthan(), a > b),
            (u32_lessthanorequal(), a <= b),
            (u32_greaterthanorequal(), a >= b),
        ];

        for (comparison, expected) in cases {
            let script = script! {
                { u32_push(a) }
                { u32_push(b) }
                { comparison }
                { expected as u32 }
                OP_EQUAL
            };
            run(script);
        }
    }
}
