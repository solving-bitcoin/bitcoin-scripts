//! Checked reduction of a byte-oriented u32 word modulo 65,537.

use super::stack::verify_canonical_byte;
use crate::support::{script::*, script_ops::OP_256MUL};

fn join_two_bytes() -> Script {
    script! {
        { verify_canonical_byte() } OP_TOALTSTACK
        { verify_canonical_byte() } { OP_256MUL() }
        OP_FROMALTSTACK OP_ADD
    }
}

/// Consume four canonical ScriptNum bytes, most significant byte first,
/// and return the represented integer modulo 65,537 as a canonical ScriptNum.
///
/// Before: `preserved | byte[0] byte[1] byte[2] byte[3]` (byte[3] on top).
/// After: `preserved | residue`, with residue in `0..=65536`.
/// Existing main/alt-stack state is preserved; the fragment requires seven
/// combined items plus preserved state. No hints or table are used. A caller
/// supplies the terminal predicate and its own resource/clean-stack accounting.
///
/// Since 65,536 = -1 modulo 65,537, the low 16-bit lane minus the high lane
/// is congruent to the entire word. The difference lies in -65,535..=65,535,
/// so a single conditional addition produces the canonical residue.
pub fn u32_mod65537() -> Script {
    script! {
        { join_two_bytes() } OP_TOALTSTACK
        { join_two_bytes() }
        OP_FROMALTSTACK OP_SWAP OP_SUB
        OP_DUP 0 OP_LESSTHAN
        OP_IF 65537 OP_ADD OP_ENDIF
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::execution::execute_script_with_inputs_strict;

    fn check(value: u32) {
        let witness = value
            .to_be_bytes()
            .map(|byte| {
                let mut bytes = [0u8; 8];
                let len = bitcoin::script::write_scriptint(&mut bytes, i64::from(byte));
                bytes[..len].to_vec()
            })
            .to_vec();
        let result = execute_script_with_inputs_strict(
            script! { { u32_mod65537() } { value % 65537 } OP_EQUAL },
            witness,
        );
        assert!(result.success, "value={value:08x}: {result}");
        assert_eq!(result.final_stack.len(), 1);
    }

    #[test]
    fn boundary_lanes_and_deterministic_words_match_unsigned_remainder() {
        for value in [
            0,
            1,
            65535,
            65536,
            65537,
            0x7fffffff,
            0x80000000,
            u32::MAX,
            0x12345678,
            0xfedcba98,
        ] {
            check(value);
        }
        for lane in [0u32, 1, 255, 256, 32767, 32768, 65534, 65535] {
            for other in [0u32, 1, 255, 256, 32767, 32768, 65534, 65535] {
                check((lane << 16) | other);
            }
        }
        for i in 0u32..256 {
            check(i.wrapping_mul(0x9e3779b9).rotate_left(i % 32));
        }
    }

    #[test]
    fn every_byte_value_at_every_lane_is_checked_and_reduced() {
        for position in 0..4 {
            for value in 0..=255u32 {
                let mut bytes = [0x12, 0x34, 0x56, 0x78];
                bytes[position] = value as u8;
                check(u32::from_be_bytes(bytes));
            }
        }
    }
}
