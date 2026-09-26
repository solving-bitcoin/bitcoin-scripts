use crate::arithmetic::bigint::BigIntImpl;
use crate::support::script::*;

impl<const N_BITS: u32, const LIMB_SIZE: u32> BigIntImpl<N_BITS, LIMB_SIZE> {
    /// Compute the difference of two BigInts
    pub fn sub(a: u32, b: u32) -> Script {
        script! {
            {Self::zip(a, b)}

            { 1 << LIMB_SIZE }

            // A0 - B0
            limb_sub_borrow OP_TOALTSTACK

            // from     A1      - (B1        + borrow_0)
            //   to     A{N-2}  - (B{N-2}    + borrow_{N-3})
            for _ in 0..Self::N_LIMBS - 2 {
                OP_ROT
                OP_ADD
                OP_SWAP
                limb_sub_borrow OP_TOALTSTACK
            }

            // A{N-1} - (B{N-1} + borrow_{N-2})
            OP_NIP
            OP_ADD
            { limb_sub_noborrow(Self::HEAD_OFFSET) }

            for _ in 0..Self::N_LIMBS - 1 {
                OP_FROMALTSTACK
            }
        }
    }

    /// Subtract two canonical BigInts when no limb borrow is possible.
    ///
    /// Each corresponding pair must satisfy `a_i >= b_i`. The inputs are
    /// consumed and the exact difference is returned in the same layout.
    pub fn sub_noborrow(a: u32, b: u32) -> Script {
        script! {
            { Self::zip(a, b) }
            for _ in 0..Self::N_LIMBS - 1 {
                { limb_sub_noborrow_checked() }
                OP_TOALTSTACK
            }
            { limb_sub_noborrow_checked() }
            OP_TOALTSTACK
            for _ in 0..Self::N_LIMBS {
                OP_FROMALTSTACK
            }
        }
    }

    pub fn neg() -> Script {
        script! {                               // ... a_n
            { (1 << LIMB_SIZE) - 1 }            // ... a_n x

            for _ in 0..Self::N_LIMBS-2 {       // ... a_{i-1} a_i x
                OP_TUCK                         // ... a_{i-1} x a_i x
                OP_SWAP                         // ... a_{i-1} x x a_i
                OP_SUB                          // ... a_{i-1} x x-a_i
                OP_TOALTSTACK                   // ... a_{i-1} x
            }
                                                // a_0 a_1 x
            OP_SWAP                             // a_0 x a_1
            OP_SUB                              // a_0 x-a_1
            OP_TOALTSTACK                       // a_0

            { Self::HEAD_OFFSET-1 }
            OP_SWAP
            OP_SUB

            for _ in 0..Self::N_LIMBS-1 {
                OP_FROMALTSTACK
            }
            { Self::add1() }
        }
    }
}

/// Compute the difference of two limbs, including the carry bit
///
/// Author: @stillsaiko
pub fn limb_sub_borrow() -> Script {
    script! {
        OP_ROT OP_ROT
        OP_SUB
        OP_DUP
        0
        OP_LESSTHAN
        OP_TUCK
        OP_IF
            2 OP_PICK OP_ADD
        OP_ENDIF
    }
}

/// Compute the sum of two limbs, dropping the carry bit
///
/// Author: @weikengchen
pub fn limb_sub_noborrow(head_offset: u32) -> Script {
    script! {
        OP_SUB
        OP_DUP
        0
        OP_LESSTHAN
        OP_IF
            { head_offset }
            OP_ADD
        OP_ENDIF
    }
}

fn limb_sub_noborrow_checked() -> Script {
    script! {
        OP_SUB
    OP_DUP
    0
    OP_LESSTHAN
    OP_NOT
    OP_VERIFY
    }
}

#[cfg(test)]
mod test {
    use crate::arithmetic::bigint::{U254, U64};
    use crate::support::execution::run;
    use crate::support::script::*;
    use core::ops::{Rem, Shl};
    use num_bigint::{BigUint, RandomBits};
    use num_traits::One;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_sub() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        for _ in 0..100 {
            let a: BigUint = prng.sample(RandomBits::new(254));
            let b: BigUint = prng.sample(RandomBits::new(254));
            let mut c: BigUint = BigUint::one().shl(254) + &a - &b;
            c = c.rem(BigUint::one().shl(254));

            let script = script! {
                { U254::push_u32_le(&a.to_u32_digits()) }
                { U254::push_u32_le(&b.to_u32_digits()) }
                { U254::sub(1, 0) }
                { U254::push_u32_le(&c.to_u32_digits()) }
                { U254::equalverify(1, 0) }
                OP_TRUE
            };
            run(script);

            let script = script! {
                { U254::push_u32_le(&b.to_u32_digits()) }
                { U254::push_u32_le(&a.to_u32_digits()) }
                { U254::sub(0, 1) }
                { U254::push_u32_le(&c.to_u32_digits()) }
                { U254::equalverify(1, 0) }
                OP_TRUE
            };
            run(script);
        }

        for _ in 0..100 {
            let a: BigUint = prng.sample(RandomBits::new(64));
            let b: BigUint = prng.sample(RandomBits::new(64));
            let mut c: BigUint = BigUint::one().shl(64) + &a - &b;
            c = c.rem(BigUint::one().shl(64));

            let script = script! {
                { U64::push_u32_le(&a.to_u32_digits()) }
                { U64::push_u32_le(&b.to_u32_digits()) }
                { U64::sub(1, 0) }
                { U64::push_u32_le(&c.to_u32_digits()) }
                { U64::equalverify(1, 0) }
                OP_TRUE
            };
            run(script);

            let script = script! {
                { U64::push_u32_le(&b.to_u32_digits()) }
                { U64::push_u32_le(&a.to_u32_digits()) }
                { U64::sub(0, 1) }
                { U64::push_u32_le(&c.to_u32_digits()) }
                { U64::equalverify(1, 0) }
                OP_TRUE
            };
            run(script);
        }
    }

    #[test]
    fn test_sub_noborrow() {
        let mut prng = ChaCha20Rng::seed_from_u64(2);
        for _ in 0..100 {
            let mut a = BigUint::default();
            let mut b = BigUint::default();
            for i in 0..U254::N_LIMBS {
                let radix = if i + 1 == U254::N_LIMBS {
                    U254::HEAD_OFFSET
                } else {
                    1 << U254::LIMB_SIZE
                };
                let lower = prng.gen_range(0..radix);
                let upper = prng.gen_range(lower..radix);
                a += BigUint::from(upper) << (i * U254::LIMB_SIZE);
                b += BigUint::from(lower) << (i * U254::LIMB_SIZE);
            }
            let c = &a - &b;
            run(script! {
                { U254::push_biguint(a) }
                { U254::push_biguint(b) }
                { U254::sub_noborrow(1, 0) }
                { U254::push_biguint(c) }
                { U254::equalverify(1, 0) }
                OP_TRUE
            });
        }
    }

    #[test]
    fn test_sub_noborrow_boundaries_and_hostile_limbs() {
        run(script! {
            { U64::push_u64_le(&[u64::MAX]) }
            { U64::push_zero() }
            { U64::sub_noborrow(1, 0) }
            { U64::push_u64_le(&[u64::MAX]) }
            { U64::equalverify(1, 0) }
            OP_TRUE
        });
        run(script! {
            { U64::push_u64_le(&[u64::MAX]) }
            { U64::push_u64_le(&[u64::MAX]) }
            { U64::sub_noborrow(1, 0) }
            { U64::push_zero() }
            { U64::equalverify(1, 0) }
            OP_TRUE
        });

        let underflow = crate::support::execution::execute_script(script! {
            { U64::push_zero() }
            1 0 0 0
            { U64::sub_noborrow(1, 0) }
            OP_TRUE
        });
        assert!(!underflow.success);

        let hostile = crate::support::execution::execute_script(script! {
            -1 0 0 0
            0 0 0 0
            { U64::copy(0) }
            { U64::check_validity() }
            { U64::copy(1) }
            { U64::check_validity() }
            { U64::sub_noborrow(1, 0) }
            OP_TRUE
        });
        assert!(!hostile.success);

        let oversized = crate::support::execution::execute_script(script! {
            0x10000 0 0 0
            0 0 0 0
            { U64::copy(0) }
            { U64::check_validity() }
            { U64::copy(1) }
            { U64::check_validity() }
            { U64::sub_noborrow(1, 0) }
            OP_TRUE
        });
        assert!(!oversized.success);
    }

    #[test]
    fn test_neg() {
        println!("U254.neg: {} bytes", U254::neg().len());
        let mut prng = ChaCha20Rng::seed_from_u64(0);

        let a: BigUint = prng.sample(RandomBits::new(254));

        let script = script! {
            { U254::push_zero() }
            { U254::push_u32_le(&a.to_u32_digits()) }
            { U254::sub(1, 0) }
            { U254::push_u32_le(&a.to_u32_digits()) }
            { U254::neg() }
            { U254::equalverify(1, 0) }
            OP_TRUE
        };
        run(script);
    }
}
