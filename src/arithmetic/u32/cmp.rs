use crate::treepp::*;

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
    use crate::u32::u32_std::u32_push;
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
