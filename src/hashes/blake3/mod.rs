use std::collections::HashMap;

pub mod utils;

use bitcoin::{
    hex::FromHex,
    opcodes::all::{OP_2DUP, OP_2OVER, OP_PICK, OP_SWAP},
    script::Instruction,
    ScriptBuf,
};
use bitcoin_script_stack::{optimizer, stack::StackTracker};
use itertools::Itertools;

pub use bitcoin_script::builder::StructuredScript as Script;
pub use bitcoin_script::script;

use crate::arithmetic::bigint::U256;
use crate::hashes::blake3::utils::{
    compress, compress_short_digits, get_flags_for_block, DigitWord, TablesVars,
};

const SHORT_32_SEMANTIC_TO_PHYSICAL_WORD: [usize; 8] = [6, 0, 5, 2, 1, 7, 4, 3];
const SHORT_32_PHYSICAL_TO_SEMANTIC_WORD: [usize; 8] = [1, 4, 3, 7, 6, 2, 0, 5];
// Each entry maps a physical position within a word to its semantic nibble.
const SHORT_32_PHYSICAL_TO_SEMANTIC_DIGIT: [usize; 8] = [7, 0, 5, 6, 1, 2, 3, 4];

fn assert_valid_limb_len(limb_len: u8) {
    assert!(
        (4..32).contains(&limb_len),
        "limb length must be in the range [4, 32)"
    );
}

fn is_opcode(instruction: &Instruction<'_>, opcode: bitcoin::Opcode) -> bool {
    matches!(instruction, Instruction::Op(candidate) if *candidate == opcode)
}

fn is_small_integer(instruction: &Instruction<'_>, value: u8) -> bool {
    matches!(instruction, Instruction::Op(opcode) if opcode.to_u8() == 0x50 + value)
}

fn optimize_stack_identities(script: ScriptBuf) -> ScriptBuf {
    let instructions = script
        .instructions_minimal()
        .map(Result::unwrap)
        .collect::<Vec<_>>();
    let mut optimized = ScriptBuf::new();
    let mut index = 0;
    while index < instructions.len() {
        if index + 3 < instructions.len()
            && is_small_integer(&instructions[index], 3)
            && is_opcode(&instructions[index + 1], OP_PICK)
            && is_small_integer(&instructions[index + 2], 3)
            && is_opcode(&instructions[index + 3], OP_PICK)
        {
            optimized.push_opcode(OP_2OVER);
            index += 4;
            continue;
        }
        if index + 2 < instructions.len()
            && is_opcode(&instructions[index], bitcoin::opcodes::all::OP_DUP)
            && is_small_integer(&instructions[index + 1], 2)
            && is_opcode(&instructions[index + 2], OP_PICK)
        {
            optimized.push_opcode(OP_2DUP);
            optimized.push_opcode(OP_SWAP);
            index += 3;
            continue;
        }
        optimized.push_instruction(instructions[index]);
        index += 1;
    }
    optimized
}

fn optimize_to_fixed_point(mut script: ScriptBuf) -> ScriptBuf {
    loop {
        let optimized = optimize_stack_identities(optimizer::optimize(script.clone()));
        if optimized == script {
            return optimized;
        }
        script = optimized;
    }
}

fn blake3(
    stack: &mut StackTracker,
    mut msg_len: u32,
    define_var: bool,
    use_full_tables: bool,
    limb_len: u8,
) {
    assert_valid_limb_len(limb_len);

    if msg_len == 0 {
        let empty_msg_hash = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";
        let empty_msg_hash_bytearray = <[u8; 32]>::from_hex(empty_msg_hash).unwrap();
        let empty_msg_hash_nibbles = empty_msg_hash_bytearray
            .into_iter()
            .flat_map(|byte| [byte >> 4, byte & 0x0f]);

        stack.custom(
            script!(for nibble in empty_msg_hash_nibbles {
                {
                    nibble
                }
            }),
            0,
            false,
            0,
            "push empty string hash in nibble form",
        );
        stack.define(8_u32 * 8, "blake3-hash");
        return;
    }

    assert!(
        msg_len <= 1024,
        "msg length must be less than or equal to 1024 bytes"
    );
    let num_blocks = msg_len.div_ceil(64);
    let limb_count = 256u32.div_ceil(u32::from(limb_len));
    let sparse_short_block = num_blocks == 1 && msg_len <= 32;

    if define_var {
        for i in (0..num_blocks).rev() {
            stack.define(limb_count, &format!("msg{}p0", i));
            stack.define(limb_count, &format!("msg{}p1", i));
        }
    }

    for _ in 0..num_blocks {
        stack.to_altstack();
        stack.to_altstack();
    }

    stack.custom(
        script!(
            OP_DEPTH
            { 0 } OP_EQUALVERIFY
        ),
        0,
        false,
        0,
        "ensure that the stack is actually empty",
    );

    let tables = TablesVars::new(stack, use_full_tables);

    for _ in 0..num_blocks {
        stack.from_altstack();
        stack.from_altstack();
    }

    for i in 0..num_blocks {
        if i == num_blocks - 1 && msg_len <= 32 {
            stack.custom(
                script!(
                    for _ in 0..limb_count / 2 {
                        OP_2DROP
                    }
                    if limb_count % 2 == 1 {
                        OP_DROP
                    }

                    if !sparse_short_block {
                        // This half-block is outside the declared message.
                        // Avoid validating and unpacking ignored witness
                        // values, then synthesize the zero padding expected by
                        // the generic compression path.
                        OP_0 OP_DUP OP_2DUP
                        for _ in 0..20 {
                            OP_3DUP
                        }
                        for _ in 0..64 {
                            OP_TOALTSTACK
                        }
                    }
                ),
                1,
                false,
                0,
                &format!("replace ignored msg{}p1 with padding", i),
            );
        } else {
            stack.custom(
                script!(
                    {U256::verify_bigint_on_stack_with_limb_size(u32::from(limb_len))}
                    {U256::transform_limbsize(u32::from(limb_len), 4)}
                    for _ in 0..64{
                        OP_TOALTSTACK
                    }
                ),
                1,
                false,
                0,
                &format!("unpack msg{}p1", i),
            );
        }

        stack.custom(
            script!(
                {U256::verify_bigint_on_stack_with_limb_size(u32::from(limb_len))}
                {U256::transform_limbsize(u32::from(limb_len), 4)}
                if !sparse_short_block {
                    for _ in 0..64{
                        OP_FROMALTSTACK
                    }
                }
            ),
            1,
            false,
            0,
            &format!("unpack msg{}p0", i),
        );

        if !sparse_short_block && i == (num_blocks - 1) && msg_len != 64 {
            let j = msg_len % 4;
            let pad_bytes = 64 + j - msg_len - 4;

            stack.custom(
                script!(
                    for _ in 0..pad_bytes {
                        OP_2DROP
                    }

                    for _ in 0..(j*2) {
                        OP_TOALTSTACK
                    }

                    for _ in 0..(4-j) {
                        OP_2DROP
                    }

                    for j in 0..(4-j) * 2 {
                        if j <= 1 {
                            OP_0
                        } else if j % 2 == 1 {
                            OP_2DUP
                        }
                    }

                    for _ in 0..(j*2){
                        OP_FROMALTSTACK
                    }

                    for j in 0..(pad_bytes*2) {
                        if j <= 1 {
                            OP_0
                        } else if j % 2 == 1 {
                            OP_2DUP
                        }
                    }
                ),
                0,
                false,
                0,
                "padding",
            );
        }

        if sparse_short_block {
            let message_word_count = msg_len.div_ceil(4);
            let partial_word_bytes = msg_len % 4;
            let unused_word_nibbles = (8 - message_word_count) * 8;
            let partial_word_nibbles = partial_word_bytes * 2;
            let partial_padding_nibbles = 8 - partial_word_nibbles;

            stack.custom(
                script! {
                    for _ in 0..unused_word_nibbles / 2 {
                        OP_2DROP
                    }

                    if partial_word_bytes != 0 {
                        for _ in 0..partial_word_nibbles {
                            OP_TOALTSTACK
                        }
                        for _ in 0..partial_padding_nibbles / 2 {
                            OP_2DROP
                        }
                        for _ in 0..partial_padding_nibbles {
                            OP_0
                        }
                        for _ in 0..partial_word_nibbles {
                            OP_FROMALTSTACK
                        }
                    }
                },
                0,
                false,
                0,
                "discard sparse short-block padding",
            );
        }

        let mut original_message = Vec::new();
        let message_word_count = if sparse_short_block {
            msg_len.div_ceil(4)
        } else {
            16
        };
        for i in 0..message_word_count {
            let m = stack.define(8, &format!("msg_{}", i));
            original_message.push(m);
        }

        let mut message = HashMap::new();
        for m in 0..message_word_count {
            message.insert(m as u8, original_message[m as usize]);
        }

        compress(
            stack,
            i != 0,
            0,
            msg_len.min(64),
            get_flags_for_block(i, num_blocks),
            message,
            &tables,
            8,
            i == num_blocks - 1,
            false,
        );

        for _ in 0..8 {
            stack.drop(stack.get_var_from_stack(0));
        }

        if msg_len > 64 {
            msg_len -= 64;
        }
    }
    tables.drop(stack);

    stack.from_altstack_joined(8_u32 * 8, "blake3-hash");
}

fn chunk_message(message_bytes: &[u8]) -> Vec<[u8; 64]> {
    let len = message_bytes.len();
    let needed_padding_bytes = if len % 64 == 0 { 0 } else { 64 - (len % 64) };

    message_bytes
        .iter()
        .copied()
        .chain(std::iter::repeat_n(0u8, needed_padding_bytes))
        .chunks(4)
        .into_iter()
        .flat_map(|chunk| chunk.collect::<Vec<u8>>().into_iter().rev())
        .chunks(64)
        .into_iter()
        .map(|mut chunk| std::array::from_fn(|_| chunk.next().unwrap()))
        .collect()
}

fn pack_256_bits(bytes: &[u8], limb_len: u8) -> Vec<u32> {
    debug_assert_eq!(bytes.len(), 32);

    let limb_bits = u32::from(limb_len);
    let limb_mask = (1_u64 << limb_bits) - 1;
    let mut accumulator = 0_u64;
    let mut accumulator_bits = 0_u32;
    let mut limbs = Vec::with_capacity(256_usize.div_ceil(usize::from(limb_len)));

    for byte in bytes.iter().rev() {
        accumulator |= u64::from(*byte) << accumulator_bits;
        accumulator_bits += 8;

        while accumulator_bits >= limb_bits {
            limbs.push((accumulator & limb_mask) as u32);
            accumulator >>= limb_bits;
            accumulator_bits -= limb_bits;
        }
    }

    if accumulator_bits != 0 {
        limbs.push(accumulator as u32);
    }

    limbs.reverse();
    limbs
}

pub fn blake3_push_message_script_with_limb(message_bytes: &[u8], limb_len: u8) -> Script {
    assert!(
        message_bytes.len() <= 1024,
        "This BLAKE3 implementation doesn't support messages longer than 1024 bytes"
    );
    assert_valid_limb_len(limb_len);
    let chunks = chunk_message(message_bytes);
    let mut limbs = Vec::new();

    for chunk in chunks.into_iter().rev() {
        for half in chunk.chunks_exact(32) {
            limbs.extend(pack_256_bits(half, limb_len));
        }
    }

    script! {
        for limb in limbs {
            {limb}
        }
    }
}

const SUM_OF_FULL_TABLES: usize = 331;
const UNPACKED_BLOCK: usize = 128;
const MAX_BLAKE3_ELEMENT_COUNT: usize = SUM_OF_FULL_TABLES + UNPACKED_BLOCK + 132;

pub fn maximum_number_of_altstack_elements_using_blake3(message_len: usize, limb_len: u8) -> i32 {
    assert!(
        message_len <= 1024,
        "This BLAKE3 implementation doesn't support messages longer than 1024 bytes"
    );
    assert_valid_limb_len(limb_len);

    if message_len == 0 {
        return 1000 - 64;
    }

    let n = message_len.div_ceil(64);
    let limb_count = 256usize.div_ceil(limb_len as usize) * 2;
    let m = (n - 1) * limb_count;
    1000_i32 - MAX_BLAKE3_ELEMENT_COUNT as i32 - m as i32
}

pub fn blake3_compute_script_with_limb(message_len: usize, limb_len: u8) -> Script {
    assert!(
        message_len <= 1024,
        "This BLAKE3 implementation doesn't support messages longer than 1024 bytes"
    );
    let mut stack = StackTracker::new();
    let use_full_tables = true;
    let message_len = message_len as u32;
    blake3(&mut stack, message_len, true, use_full_tables, limb_len);
    Script::new("optimized BLAKE3")
        .push_script(optimize_to_fixed_point(stack.get_script().compile()))
}

pub fn blake3_compute_script(message_len: usize) -> Script {
    blake3_compute_script_with_limb(message_len, 29)
}

fn blake3_short(stack: &mut StackTracker, message_len: u32) {
    assert!(
        (1..=32).contains(&message_len),
        "short BLAKE3 message length must be in the range [1, 32]"
    );

    let input_nibbles = message_len * 2;
    stack.define(input_nibbles, "short message nibbles");
    stack.custom_ex(
        script! {
            for _ in 0..input_nibbles {
                OP_DUP
                0
                16
                OP_WITHIN
                OP_VERIFY
                OP_TOALTSTACK
            }
            OP_DEPTH
            0
            OP_EQUALVERIFY
        },
        1,
        vec![],
        input_nibbles,
    );

    let message_word_count = message_len.div_ceil(4);
    let mut tables = if message_word_count == 8 {
        TablesVars::new_late(stack)
    } else {
        TablesVars::new(stack, true)
    };
    let input = stack.from_altstack_joined(input_nibbles, "validated short message nibbles");
    let partial_word_bytes = message_len % 4;
    let partial_word_nibbles = partial_word_bytes * 2;
    let partial_padding_nibbles = if partial_word_bytes == 0 {
        0
    } else {
        8 - partial_word_nibbles
    };
    let output_words = if message_word_count == 8 {
        (0..message_word_count * 8)
            .map(|index| (1, format!("msg_digit_{index}")))
            .collect()
    } else {
        (0..message_word_count)
            .map(|index| (8, format!("msg_{index}")))
            .collect()
    };
    let message_words = stack.custom_ex(
        script! {
            if partial_word_bytes != 0 {
                for _ in 0..partial_word_nibbles {
                    OP_TOALTSTACK
                }
                for _ in 0..partial_padding_nibbles {
                    OP_0
                }
                for _ in 0..partial_word_nibbles {
                    OP_FROMALTSTACK
                }
            }
        },
        1,
        output_words,
        0,
    );
    debug_assert_eq!(input.size(), input_nibbles);

    if message_word_count == 8 {
        let digit_order = if message_len == 32 {
            SHORT_32_PHYSICAL_TO_SEMANTIC_DIGIT
        } else {
            [0, 1, 2, 3, 4, 5, 6, 7]
        };
        let physical_words = message_words
            .chunks_exact(8)
            .map(|digits| DigitWord::from_physical_slice(digits, &digit_order))
            .collect::<Vec<_>>();
        let message = (0..message_word_count as usize)
            .map(|semantic_index| {
                (
                    semantic_index as u8,
                    physical_words[if message_len == 32 {
                        SHORT_32_SEMANTIC_TO_PHYSICAL_WORD[semantic_index]
                    } else {
                        semantic_index
                    }],
                )
            })
            .collect();
        tables.push_late_tables(stack);
        compress_short_digits(stack, message_len, message, &tables);
    } else {
        let message = (0..message_word_count as usize)
            .map(|semantic_index| (semantic_index as u8, message_words[semantic_index]))
            .collect();
        compress(
            stack,
            false,
            0,
            message_len,
            get_flags_for_block(0, 1),
            message,
            &tables,
            8,
            true,
            true,
        );
    }

    for _ in 0..8 {
        stack.drop(stack.get_var_from_stack(0));
    }
    if message_len == 32 {
        tables.drop_after_destructive_xor_query(stack);
    } else {
        tables.drop(stack);
    }
    stack.from_altstack_joined(64, "blake3-hash");
}

fn blake3_short_message_nibbles(message: &[u8]) -> Vec<u8> {
    assert!(
        message.len() <= 32,
        "short BLAKE3 messages must be at most 32 bytes"
    );
    let physical_to_semantic = if message.len() == 32 {
        SHORT_32_PHYSICAL_TO_SEMANTIC_WORD.as_slice()
    } else {
        &[]
    };
    let word_count = message.len().div_ceil(4);
    let semantic_nibbles = (0..word_count)
        .map(|physical_index| {
            physical_to_semantic
                .get(physical_index)
                .copied()
                .unwrap_or(physical_index)
        })
        .flat_map(|semantic_index| {
            let start = semantic_index * 4;
            let end = (start + 4).min(message.len());
            message[start..end].iter().rev()
        })
        .flat_map(|byte| [byte >> 4, byte & 0x0f])
        .collect::<Vec<_>>();
    if message.len() == 32 {
        semantic_nibbles
            .chunks_exact(8)
            .flat_map(|word| {
                SHORT_32_PHYSICAL_TO_SEMANTIC_DIGIT
                    .iter()
                    .map(|index| word[*index])
            })
            .collect()
    } else {
        semantic_nibbles
    }
}

/// Returns minimally encoded witness items for [`blake3_short_compute_script`].
///
/// Four-byte words use BLAKE3's little-endian byte order. At exactly 32 bytes,
/// words and their nibble registers are physically permuted to reduce stack
/// routing; this helper applies both permutations.
pub fn blake3_short_message_witness(message: &[u8]) -> Vec<Vec<u8>> {
    blake3_short_message_nibbles(message)
        .into_iter()
        .map(|nibble| if nibble == 0 { vec![] } else { vec![nibble] })
        .collect()
}

/// Pushes a short message in the same routed nibble layout as
/// [`blake3_short_message_witness`].
pub fn blake3_push_short_message_script(message: &[u8]) -> Script {
    let nibbles = blake3_short_message_nibbles(message);

    script! {
        for nibble in nibbles {
            {nibble}
        }
    }
}

/// Computes unkeyed BLAKE3 for a witness-backed message of at most 32 bytes.
///
/// The input is two numeric nibble items per message byte in the layout emitted
/// by [`blake3_push_short_message_script`]. Every nibble is range-checked before
/// it can address lookup memory. The declared length is fixed in the generated
/// script, and the main stack must contain exactly those input items.
pub fn blake3_short_compute_script(message_len: usize) -> Script {
    if message_len == 0 {
        return blake3_compute_script(0);
    }
    assert!(
        message_len <= 32,
        "short BLAKE3 messages must be at most 32 bytes"
    );

    let mut stack = StackTracker::new();
    blake3_short(&mut stack, message_len as u32);
    Script::new("optimized short BLAKE3")
        .push_script(optimize_to_fixed_point(stack.get_script().compile()))
}

pub fn blake3_verify_output_script(expected_output: [u8; 32]) -> Script {
    let expected_nibbles = expected_output
        .into_iter()
        .flat_map(|byte| [byte >> 4, byte & 0x0f])
        .rev()
        .collect::<Vec<_>>();

    script! {
        for (index, nibble) in expected_nibbles.iter().enumerate() {
            {*nibble}
            if index + 1 == expected_nibbles.len() {
                OP_EQUAL
            } else {
                OP_EQUALVERIFY
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::execution::{
        execute_script, execute_script_buf_without_stack_limit, execute_script_with_inputs,
    };
    use bitcoin::ScriptBuf;

    const USEFUL_LIMB_LENGTHS: [u8; 2] = [4, 29];

    fn final_stack(script: Script) -> (bool, Vec<Vec<u8>>) {
        let result = execute_script(script);
        let stack = (0..result.final_stack.len())
            .map(|index| result.final_stack.get(index))
            .collect();
        (result.success, stack)
    }

    #[test]
    fn stack_identity_peepholes_are_exact() {
        let values = [-1_i32, 0, 1, 17];
        for a in values {
            for b in values {
                for c in values {
                    for d in values {
                        let original = final_stack(script! {
                            { a } { b } { c } { d }
                            { 3 } OP_PICK { 3 } OP_PICK OP_TRUE
                        });
                        let replacement = final_stack(script! {
                            { a } { b } { c } { d }
                            OP_2OVER OP_TRUE
                        });
                        assert_eq!(original, replacement, "2OVER: {a} {b} {c} {d}");
                    }
                }
            }
        }
        for a in values {
            for b in values {
                let original = final_stack(script! {
                    { a } { b } OP_DUP { 2 } OP_PICK OP_TRUE
                });
                let replacement = final_stack(script! {
                    { a } { b } OP_2DUP OP_SWAP OP_TRUE
                });
                assert_eq!(original, replacement, "2DUP SWAP: {a} {b}");
            }
        }

        // Symbolically compare every shallow depth, including failure.
        let pick = |stack: &mut Vec<usize>, depth: usize| {
            let index = stack.len().checked_sub(depth + 1)?;
            stack.push(stack[index]);
            Some(())
        };
        for depth in 0..=8 {
            let mut original = (0..depth).collect::<Vec<_>>();
            let original = pick(&mut original, 3)
                .and_then(|()| pick(&mut original, 3))
                .map(|()| original);
            let mut replacement = (0..depth).collect::<Vec<_>>();
            let replacement = (depth >= 4).then(|| {
                replacement.extend([replacement[depth - 4], replacement[depth - 3]]);
                replacement
            });
            assert_eq!(original, replacement, "2OVER depth {depth}");

            let mut original = (0..depth).collect::<Vec<_>>();
            let original = original.last().copied().and_then(|top| {
                original.push(top);
                pick(&mut original, 2).map(|()| original)
            });
            let mut replacement = (0..depth).collect::<Vec<_>>();
            let replacement = (depth >= 2).then(|| {
                replacement.extend([replacement[depth - 1], replacement[depth - 2]]);
                replacement
            });
            assert_eq!(original, replacement, "2DUP SWAP depth {depth}");
        }

        let once = optimize_stack_identities(
            script! {
                { 3 } OP_PICK { 3 } OP_PICK
                OP_DUP { 2 } OP_PICK
            }
            .compile(),
        );
        assert_eq!(once, script! { OP_2OVER OP_2DUP OP_SWAP }.compile());
        assert_eq!(optimize_stack_identities(once.clone()), once);

        let exact32 = blake3_short_compute_script(32).compile();
        assert_eq!(optimize_to_fixed_point(exact32.clone()), exact32);
    }

    fn verify_blake_output_with_limbs(message: &[u8], expected_hash: [u8; 32], limb_lens: &[u8]) {
        for limb_len in limb_lens.iter().copied() {
            let mut bytes = blake3_push_message_script_with_limb(message, limb_len)
                .compile()
                .to_bytes();
            bytes.extend(
                blake3_compute_script_with_limb(message.len(), limb_len)
                    .compile()
                    .to_bytes(),
            );
            bytes.extend(
                blake3_verify_output_script(expected_hash)
                    .compile()
                    .to_bytes(),
            );
            let script = ScriptBuf::from_bytes(bytes);
            assert!(execute_script_buf_without_stack_limit(script).success);
        }
    }

    fn verify_blake_outputs_cached_with_limbs<const LEN: usize>(
        messages: &[[u8; LEN]],
        expected_hashes: &[[u8; 32]],
        limb_lens: &[u8],
    ) {
        assert_eq!(messages.len(), expected_hashes.len());
        for limb_len in limb_lens.iter().copied() {
            let compute = blake3_compute_script_with_limb(LEN, limb_len).compile();
            for (i, message) in messages.iter().enumerate() {
                let expected_hash = expected_hashes[i];
                let mut bytes = blake3_push_message_script_with_limb(message, limb_len)
                    .compile()
                    .to_bytes();
                bytes.extend_from_slice(compute.as_bytes());
                bytes.extend(
                    blake3_verify_output_script(expected_hash)
                        .compile()
                        .to_bytes(),
                );
                let script = ScriptBuf::from_bytes(bytes);
                assert!(execute_script_buf_without_stack_limit(script).success);
            }
        }
    }

    #[test]
    fn test_zero_length() {
        let message = [];
        let expected_hash = *blake3::hash(&message).as_bytes();
        verify_blake_output_with_limbs(&message, expected_hash, &USEFUL_LIMB_LENGTHS);
    }

    #[test]
    fn test_short_direct_nibbles_all_lengths() {
        for message_len in 0..=32 {
            let message = (0..message_len)
                .map(|index| ((index * 73 + message_len * 19) & 0xff) as u8)
                .collect::<Vec<_>>();
            let expected_hash = *blake3::hash(&message).as_bytes();
            let compute = blake3_short_compute_script(message_len);
            let verify = blake3_verify_output_script(expected_hash);
            let result = execute_script(script! {
                { blake3_push_short_message_script(&message) }
                { compute.clone() }
                { verify.clone() }
            });
            assert!(result.success, "length {message_len}: {result}");
            assert!(
                result.stats.max_nb_stack_items <= 1000,
                "length {message_len} peaked at {} stack items",
                result.stats.max_nb_stack_items
            );

            let witness_result = execute_script_with_inputs(
                script! {
                    { compute }
                    { verify }
                },
                blake3_short_message_witness(&message),
            );
            assert!(
                witness_result.success,
                "witness length {message_len}: {witness_result}"
            );
        }
    }

    #[test]
    fn test_short_direct_nibbles_reject_malformed_inputs() {
        let compute = blake3_short_compute_script(1);
        for invalid_nibble in [-1, 16] {
            let result = execute_script(script! {
                { 0 }
                { invalid_nibble }
                { compute.clone() }
            });
            assert!(!result.success);
        }

        let too_few = execute_script(script! {
            { 0 }
            { compute.clone() }
        });
        assert!(!too_few.success);

        let extra = execute_script(script! {
            { 0 }
            { 0 }
            { 0 }
            { compute }
        });
        assert!(!extra.success);
    }

    #[test]
    #[should_panic(expected = "short BLAKE3 messages must be at most 32 bytes")]
    fn test_short_direct_nibbles_reject_long_messages() {
        blake3_short_compute_script(33);
    }

    #[test]
    fn test_max_length() {
        let message = [0x00; 1024];
        let expected_hash = *blake3::hash(&message).as_bytes();
        verify_blake_output_with_limbs(&message, expected_hash, &USEFUL_LIMB_LENGTHS);
    }

    #[test]
    #[should_panic(
        expected = "This BLAKE3 implementation doesn't support messages longer than 1024 bytes"
    )]
    fn test_too_long() {
        let message = [0x00; 1025];
        let expected_hash = *blake3::hash(&message).as_bytes();
        verify_blake_output_with_limbs(&message, expected_hash, &USEFUL_LIMB_LENGTHS);
    }

    #[test]
    fn test_single_byte() {
        let messages: Vec<[u8; 1]> = (0..=255).map(|byte| [byte]).collect();
        let expected_hashes: Vec<[u8; 32]> = messages
            .iter()
            .map(|message| *blake3::hash(message).as_bytes())
            .collect();
        verify_blake_outputs_cached_with_limbs(&messages, &expected_hashes, &USEFUL_LIMB_LENGTHS);
    }

    #[test]
    fn test_full_block_and_31_bit_limbs() {
        let message: [u8; 64] = std::array::from_fn(|index| index as u8);
        let expected_hash = *blake3::hash(&message).as_bytes();
        verify_blake_output_with_limbs(&message, expected_hash, &[4, 29, 31]);
    }

    #[test]
    fn test_half_and_full_block_boundaries() {
        for message_len in [31, 32, 33, 63, 64, 65] {
            let message = (0..251_u8).cycle().take(message_len).collect::<Vec<_>>();
            let expected_hash = *blake3::hash(&message).as_bytes();
            verify_blake_output_with_limbs(&message, expected_hash, &[29]);
        }
    }

    #[test]
    fn test_compute_script_is_optimizer_fixed_point() {
        for message_len in [64, 1024] {
            let script = blake3_compute_script_with_limb(message_len, 29).compile();
            assert_eq!(optimize_to_fixed_point(script.clone()), script);
        }

        let short = blake3_short_compute_script(32).compile();
        assert_eq!(optimize_to_fixed_point(short.clone()), short);
    }

    #[test]
    #[should_panic(expected = "limb length must be in the range [4, 32)")]
    fn test_invalid_limb_length_for_empty_message() {
        blake3_compute_script_with_limb(0, 3);
    }

    fn test_official_test_vectors_with_limbs(limb_lens: &[u8]) {
        use serde::Deserialize;
        use std::fs::File;
        use std::io::BufReader;

        #[derive(Debug, Deserialize)]
        struct TestVectors {
            cases: Vec<TestVector>,
        }

        #[derive(Debug, Deserialize)]
        struct TestVector {
            input_len: usize,
            hash: String,
        }

        fn read_test_vectors() -> Vec<(Vec<u8>, [u8; 32])> {
            let path = "src/hashes/blake3/test_vectors.json";
            let file = File::open(path).unwrap();
            let reader = BufReader::new(file);
            let test_vectors: TestVectors = serde_json::from_reader(reader).unwrap();
            test_vectors
                .cases
                .iter()
                .filter(|vector| vector.input_len <= 1024)
                .map(|vector| {
                    let message = (0..251u8).cycle().take(vector.input_len).collect();
                    let expected_hash = <[u8; 32]>::from_hex(&vector.hash[0..64]).unwrap();
                    (message, expected_hash)
                })
                .collect()
        }

        let test_vectors = read_test_vectors();
        for (message, expected_hash) in test_vectors {
            verify_blake_output_with_limbs(&message, expected_hash, limb_lens);
        }
    }

    #[test]
    fn test_official_test_vectors() {
        test_official_test_vectors_with_limbs(&USEFUL_LIMB_LENGTHS)
    }

    fn test_blake3_stack_space(
        blake3_script: Script,
        message_len: usize,
        limb_len: u8,
        extra_elements: i32,
    ) -> bool {
        let message = vec![0u8; message_len];
        execute_script(script! {
            for _ in 0..extra_elements {
                { -1 } OP_TOALTSTACK
            }
            { blake3_push_message_script_with_limb(&message, limb_len) }
            { blake3_script.clone() }
            for _ in 0..extra_elements {
                OP_FROMALTSTACK OP_DROP
            }
            for _ in 0..64 {
                OP_DROP
            }
            OP_TRUE
        })
        .success
    }

    fn test_maximum_alstack_element_calculation_with_limbs(limb_lens: &[u8]) {
        for limb_len in limb_lens.iter().copied() {
            for message_len in std::iter::once(0).chain((64..=1024).step_by(64)) {
                let blake3_script = blake3_compute_script_with_limb(message_len, limb_len);
                let maximum_extra_elements =
                    maximum_number_of_altstack_elements_using_blake3(message_len, limb_len);
                if maximum_extra_elements < 0 {
                    assert!(!test_blake3_stack_space(
                        blake3_script.clone(),
                        message_len,
                        limb_len,
                        0
                    ));
                } else {
                    assert!(test_blake3_stack_space(
                        blake3_script.clone(),
                        message_len,
                        limb_len,
                        maximum_extra_elements
                    ));
                    assert!(!test_blake3_stack_space(
                        blake3_script.clone(),
                        message_len,
                        limb_len,
                        maximum_extra_elements + 1
                    ));
                }
            }
        }
    }

    #[test]
    fn test_maximum_alstack_element_calculation() {
        test_maximum_alstack_element_calculation_with_limbs(&USEFUL_LIMB_LENGTHS);
    }

    #[test]
    fn test_failure_on_invalid_input() {
        let zero = script! {
            {0} {0} {0} {0} {0} {0} {0} {0} {0}
        };
        let fake_zero = script! {
            {0} {0} {0} {0} {0} {0} {0} {0} {-1}
        };
        let res = execute_script(script! {
            {zero.clone()} {zero.clone()} {blake3_compute_script(64)}
            for _ in 0..64 {
                OP_TOALTSTACK
            }
            {zero.clone()} {fake_zero.clone()} {blake3_compute_script(64)}
        });
        assert_eq!(res.success, false);
        assert_eq!(res.last_opcode, Some(bitcoin::opcodes::all::OP_VERIFY));
    }

    #[test]
    fn test_failure_on_oversized_input_limb() {
        let valid = script! {
            for _ in 0..9 {
                {0}
            }
        };
        let oversized_regular_limb = script! {
            for _ in 0..8 {
                {0}
            }
            {1 << 29}
        };
        let oversized_head_limb = script! {
            {1 << 24}
            for _ in 0..8 {
                {0}
            }
        };

        for invalid in [oversized_regular_limb, oversized_head_limb] {
            let result = execute_script(script! {
                {valid.clone()}
                {invalid}
                {blake3_compute_script(64)}
            });
            assert!(!result.success);
            assert_eq!(result.last_opcode, Some(bitcoin::opcodes::all::OP_VERIFY));
        }
    }

    #[test]
    fn test_ignored_final_half_block_is_not_validated() {
        let valid_message_half = script! {
            for _ in 0..9 {
                {0}
            }
        };
        let ignored_invalid_half = script! {
            for _ in 0..9 {
                {-1}
            }
        };
        let expected_hash = *blake3::hash(&[0]).as_bytes();

        let result = execute_script(script! {
            {valid_message_half}
            {ignored_invalid_half}
            {blake3_compute_script(1)}
            {blake3_verify_output_script(expected_hash)}
        });
        assert!(result.success);
    }
}
