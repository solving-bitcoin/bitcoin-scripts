//! Partial-word packed decoding to biased radix-32 digits or centered limbs.
//!
//! The eight hostile input items and their signed-word semantics match
//! [`super::u5_packed::decode_fast`]. The decoder consumes those items and
//! [`decode`] returns sixteen `[20,20,20,15 x 13]`-bit centered limbs, last
//! limb deepest and limb zero nearest the top. [`decode_digits`] returns the
//! original fifty-one biased digits instead, with digit zero nearest the top.
//! It validates the zero padding bit and the nineteen-value canonical gap.
//! It requires zero auxiliary hint items, including when invoked repeatedly.
//! The sixteen script-built power constants are included in its 62-item local
//! combined-stack peak and are removed before returning. A 937-item preserved
//! prefix therefore composes at a strict peak of 999 items.
//! The digit decoder uses the same sixteen powers and has a 93-item local
//! peak, so its corresponding 999-item frontier preserves 906 items.
//!
//! Every numeric input to arithmetic is within signed four-byte ScriptNum
//! range. Word normalization reaches at most `2^31-1`; all twenty-bit limb
//! assembly intermediates are at most `2^20-1`. Centered output bounds are
//! `[-541200,507375]` for twenty-bit limbs and `[-16912,15855]` for fifteen-bit
//! limbs. The canonical-gap sum lies in `[-1302256,1220865]`.

use crate::support::script::*;

pub const LIMB_DIGITS: [usize; 16] = [4, 4, 4, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3];
pub const HINT_ITEM_COUNT: usize = 0;
pub const INPUT_ITEM_COUNT: usize = 8;
pub const OUTPUT_ITEM_COUNT: usize = 16;
pub const SCRIPT_BYTES: usize = 3_590;
pub const STACK_ITEMS: u32 = 62;
pub const POWER_TABLE_ITEMS: usize = 16;
pub const DIGIT_SCRIPT_BYTES: usize = 4_072;
pub const DIGIT_STACK_ITEMS: u32 = 93;
pub const DIGIT_OUTPUT_ITEM_COUNT: usize = 51;

fn bias(digits: usize) -> i64 {
    16 * (0..digits).fold(0, |value, _| 32 * value + 1)
}

fn normalize_word() -> Script {
    script! {
        OP_SIZE 5 OP_NUMEQUAL
        OP_IF
            { -2_147_483_648i64 } OP_EQUALVERIFY
            1 0
        OP_ELSE
            OP_DUP 0 OP_LESSTHAN
            OP_IF
                { 0x7fff_ffffu32 } OP_ADD OP_1ADD
                1 OP_SWAP
            OP_ELSE
                0 OP_SWAP
            OP_ENDIF
        OP_ENDIF
    }
}

// Leave the low part intact and only expand the remaining high bits. The
// already-extracted bit31 is below the numeric remainder for words zero-six.
fn split_low_piece(low_bits: usize, leading_bit: bool, table_cutoff: usize) -> Script {
    script! {
        for bit in (low_bits..31).rev() {
            if bit >= table_cutoff {
                // Completed limbs and cross-word carry are on altstack. At
                // both uses this fixed depth addresses the same script-built
                // power, despite the intervening comparison result.
                OP_DUP
                { 2 + usize::from(leading_bit) + 2 * (30 - bit) } OP_PICK
                OP_GREATERTHANOREQUAL
                OP_SWAP OP_OVER
                OP_IF
                    { 2 + usize::from(leading_bit) + 2 * (30 - bit) } OP_PICK
                    OP_SUB
                OP_ENDIF
            } else {
                OP_DUP { (1u32 << bit) - 1 } OP_GREATERTHAN
                OP_SWAP OP_OVER
                OP_IF { 1u32 << bit } OP_SUB OP_ENDIF
            }
        }
    }
}

fn combine_top_bits(width: usize) -> Script {
    script! {
        for _ in 0..width { OP_TOALTSTACK }
        OP_FROMALTSTACK
        for _ in 1..width {
            OP_DUP OP_ADD OP_FROMALTSTACK OP_ADD
        }
    }
}

/// Experimental threshold-table boundary for reproducible size comparisons.
///
/// This has the same input/output contract as [`decode`], with `31-cutoff`
/// script-built power items and local peak `46+31-cutoff` instead of 62.
pub fn decode_with_table_cutoff(preserved_items: u32, table_cutoff: usize) -> Script {
    decode_partition(preserved_items, table_cutoff, &LIMB_DIGITS, true, 46)
}

fn decode_partition(
    preserved_items: u32,
    table_cutoff: usize,
    limb_digits: &[usize],
    centered: bool,
    base_peak: u64,
) -> Script {
    assert!(table_cutoff <= 31);
    let table_items = 31 - table_cutoff;
    assert!(u64::from(preserved_items) + base_peak + table_items as u64 <= 1_000);
    let limb_bias = |digits| if centered { bias(digits) } else { 0 };
    let mut limb_index = 0usize;
    let mut carry_bits = 0usize;
    let mut steps = Vec::new();
    steps.push(script! {
        for bit in table_cutoff..31 { { 1u32 << bit } }
    });
    for word_index in 0..8 {
        if table_items != 0 {
            steps.push(script! { { table_items } OP_ROLL });
        }
        steps.push(normalize_word());
        let word_bits = if word_index == 7 {
            steps.push(script! { OP_SWAP OP_NOT OP_VERIFY });
            31
        } else {
            32
        };
        let first_bits = 5 * limb_digits[limb_index] - carry_bits;
        assert!(first_bits <= word_bits);
        steps.push(split_low_piece(first_bits, word_index != 7, table_cutoff));
        steps.push(script! {
            for _ in 0..carry_bits { OP_DUP OP_ADD }
            if carry_bits != 0 { OP_FROMALTSTACK OP_ADD }
            if centered { { limb_bias(limb_digits[limb_index]) } OP_SUB }
            OP_TOALTSTACK
        });
        limb_index += 1;
        let mut remaining_bits = word_bits - first_bits;
        while limb_index < limb_digits.len() && remaining_bits >= 5 * limb_digits[limb_index] {
            let width = 5 * limb_digits[limb_index];
            steps.push(script! {
                { combine_top_bits(width) }
                if centered { { limb_bias(limb_digits[limb_index]) } OP_SUB }
                OP_TOALTSTACK
            });
            remaining_bits -= width;
            limb_index += 1;
        }
        carry_bits = remaining_bits;
        if remaining_bits != 0 {
            steps.push(script! { { combine_top_bits(remaining_bits) } OP_TOALTSTACK });
        }
    }
    assert_eq!(limb_index, limb_digits.len());
    assert_eq!(carry_bits, 0);
    script! {
        for step in steps { { step } }
        for _ in 0..table_items / 2 { OP_2DROP }
        if table_items % 2 != 0 { OP_DROP }
        for _ in 0..limb_digits.len() { OP_FROMALTSTACK }
        // All limbs are bounded by construction. The field's forbidden top
        // nineteen encodings have every high limb maximal and limb0 in the
        // final nineteen values of its interval. Since all individual limbs
        // are bounded, the sum reaches its upper bound iff every limb does.
        1 OP_PICK
        for index in 2..limb_digits.len() {
            { index + 1 } OP_PICK OP_ADD
        }
        { limb_digits[1..].iter().map(|digits| (1i64 << (5 * digits)) - 1 - limb_bias(*digits)).sum::<i64>() }
        OP_NUMEQUAL
        OP_IF
            OP_DUP { (1i64 << (5 * limb_digits[0])) - 19 - limb_bias(limb_digits[0]) }
            OP_LESSTHAN OP_VERIFY
        OP_ENDIF
    }
}

/// Consume eight compressed-u32 words and return sixteen certified centered
/// limbs. Before: `preserved | word7 .. word0`; after:
/// `preserved | limb15 .. limb0`. No terminal predicate is appended. Eight
/// data items coexist at entry; there are zero auxiliary hints per invocation
/// and zero cumulative hints for any repeated invocation count.
pub fn decode(preserved_items: u32) -> Script {
    decode_with_table_cutoff(preserved_items, 15)
}

/// Experimental partial-word stream into 51 certified biased radix-32 digits.
/// Its zero-hint eight-item input/output semantics match `decode_fast`; the
/// selected power table is removed before returning. There are `31-cutoff`
/// script-built power items and local peak `77+31-cutoff`.
pub fn decode_digits_with_table_cutoff(preserved_items: u32, table_cutoff: usize) -> Script {
    decode_partition(preserved_items, table_cutoff, &[1; 51], false, 77)
}

/// Consume eight packed items and return fifty-one certified biased digits.
/// Before: `preserved | word7 .. word0`; after:
/// `preserved | digit50 .. digit0`. This fragment adds no terminal predicate.
/// The eight input data items coexist at entry. Zero auxiliary witness hints
/// are required per invocation and for every repeated invocation count. Its
/// sixteen script-built powers are temporary and included in the 93-item
/// combined main/alt-stack bound.
pub fn decode_digits(preserved_items: u32) -> Script {
    decode_digits_with_table_cutoff(preserved_items, 15)
}
