//! Checked transposition of contiguous u32 words into byte-major planes.

use crate::support::script::*;

/// Largest checked batch whose combined main/alt-stack peak is at most 1,000.
pub const U32_BYTE_PLANES_MAX_WORDS: u32 = (1_000 - 4) / 4;

fn transpose(word_count: u32) -> Script {
    let mut remaining = (0..4 * word_count).collect::<Vec<_>>();
    let mut depths = Vec::with_capacity(4 * word_count as usize);

    // Source order is word-major, MSB first. Select desired output in reverse
    // so restoring altstack produces plane 0 through plane 3 on main.
    for plane in (0..4).rev() {
        for word in (0..word_count).rev() {
            let source = 4 * word + plane;
            let position = remaining
                .iter()
                .position(|candidate| *candidate == source)
                .expect("byte source must remain available");
            depths.push((remaining.len() - 1 - position) as u32);
            remaining.remove(position);
        }
    }

    script! {
        for depth in depths {
            { depth } OP_ROLL OP_TOALTSTACK
        }
    }
}

/// Consume contiguous u32 words and return their bytes grouped by position.
///
/// Input is `preserved | word[0] | ... | word[n-1]`, each word represented as
/// four byte items in MSB-first order. Output is
/// `preserved | byte0[0..n] | byte1[0..n] | byte2[0..n] | byte3[0..n]`.
/// When `check_inputs` is true, every byte item is constrained to `0..=255`.
pub fn u32_words_to_byte_planes(word_count: u32, check_inputs: bool) -> Script {
    assert!(word_count > 0, "word batch must not be empty");
    assert!(
        word_count <= U32_BYTE_PLANES_MAX_WORDS,
        "u32 byte-plane batch exceeds Bitcoin Script's stack limit"
    );
    let transpose = transpose(word_count);
    script! {
        // Stage the batch through altstack to install an internal delimiter
        // without knowing how many unrelated main-stack items precede it.
        for _ in 0..4 * word_count {
            OP_TOALTSTACK
        }
        OP_0
        for _ in 0..4 * word_count {
            OP_FROMALTSTACK
        }

        if check_inputs {
            for _ in 0..4 * word_count {
                OP_DUP OP_0 { 256 } OP_WITHIN OP_VERIFY
            }
        }

        { transpose }
        OP_DROP
        for _ in 0..4 * word_count {
            OP_FROMALTSTACK
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arithmetic::u32::stack::u32_push;
    use crate::support::execution::execute_script;

    fn verify(words: &[u32], expected_planes: &[u32]) {
        let result = execute_script(script! {
            for word in words {
                { u32_push(*word) }
            }
            { u32_words_to_byte_planes(words.len() as u32, true) }
            for byte in expected_planes.iter().rev() {
                { *byte } OP_EQUALVERIFY
            }
            OP_TRUE
        });
        assert!(result.success, "byte-plane transpose failed: {result}");
    }

    #[test]
    fn transposes_words_in_msb_first_order() {
        verify(
            &[0x11_22_33_44, 0xaa_bb_cc_dd],
            &[0x11, 0xaa, 0x22, 0xbb, 0x33, 0xcc, 0x44, 0xdd],
        );
    }

    #[test]
    fn preserves_unrelated_main_and_alt_stack_items() {
        let result = execute_script(script! {
            OP_7 OP_TOALTSTACK
            OP_9
            { u32_push(0x01_02_03_04) }
            { u32_words_to_byte_planes(1, true) }
            for byte in [1, 2, 3, 4].iter().rev() {
                { *byte } OP_EQUALVERIFY
            }
            OP_DROP
            OP_FROMALTSTACK OP_7 OP_EQUALVERIFY
            OP_TRUE
        });
        assert!(result.success, "stack preservation failed: {result}");
    }

    #[test]
    fn checked_mode_rejects_malformed_byte_items() {
        for invalid in [-1, 256] {
            let result = execute_script(script! {
                0 0 0 { invalid }
                { u32_words_to_byte_planes(1, true) }
                OP_TRUE
            });
            assert!(!result.success, "accepted invalid byte {invalid}");
        }
    }

    #[test]
    fn unchecked_mode_preserves_hostile_items_for_certified_callers() {
        let result = execute_script(script! {
            0 0 0 -1
            { u32_words_to_byte_planes(1, false) }
            for byte in [0, 0, 0, -1].iter().rev() {
                { *byte } OP_EQUALVERIFY
            }
            OP_TRUE
        });
        assert!(
            result.success,
            "unchecked permutation changed items: {result}"
        );
    }

    #[test]
    fn batch_guard_matches_the_strict_peak() {
        const MEASURED_WORDS: u32 = 8;
        let result = execute_script(script! {
            for _ in 0..4 * MEASURED_WORDS {
                OP_0
            }
            { u32_words_to_byte_planes(MEASURED_WORDS, true) }
            for _ in 0..4 * MEASURED_WORDS {
                OP_DROP
            }
            OP_TRUE
        });
        assert!(result.success, "measured batch failed: {result}");
        assert_eq!(
            result.stats.max_nb_stack_items,
            (4 * MEASURED_WORDS + 4) as usize
        );

        assert!(std::panic::catch_unwind(|| u32_words_to_byte_planes(0, true)).is_err());
        assert!(std::panic::catch_unwind(|| {
            u32_words_to_byte_planes(U32_BYTE_PLANES_MAX_WORDS + 1, true)
        })
        .is_err());
    }
}
