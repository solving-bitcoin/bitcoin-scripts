use std::collections::HashMap;

pub mod utils;

use bitcoin::hex::FromHex;
use bitcoin_script_stack::{optimizer, stack::StackTracker};
use itertools::Itertools;

pub use bitcoin_script::builder::StructuredScript as Script;
pub use bitcoin_script::script;

use crate::arithmetic::bigint::U256;
use crate::hashes::blake3::utils::{compress, get_flags_for_block, TablesVars};

fn assert_valid_limb_len(limb_len: u8) {
    assert!(
        (4..32).contains(&limb_len),
        "limb length must be in the range [4, 32)"
    );
}

fn optimize_to_fixed_point(mut script: bitcoin::ScriptBuf) -> bitcoin::ScriptBuf {
    loop {
        let optimized = optimizer::optimize(script.clone());
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

                    // This half-block is outside the declared message. Avoid
                    // validating and unpacking ignored witness values, then
                    // synthesize the zero padding expected by compression.
                    OP_0 OP_DUP OP_2DUP
                    for _ in 0..20 {
                        OP_3DUP
                    }
                    for _ in 0..64 {
                        OP_TOALTSTACK
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
                for _ in 0..64{
                    OP_FROMALTSTACK
                }
            ),
            1,
            false,
            0,
            &format!("unpack msg{}p0", i),
        );

        if i == (num_blocks - 1) && msg_len != 64 {
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

        let mut original_message = Vec::new();
        for i in 0..16 {
            let m = stack.define(8, &format!("msg_{}", i));
            original_message.push(m);
        }

        let mut message = HashMap::new();
        for m in 0..16 {
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

const SUM_OF_FULL_TABLES: usize = 384;
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
    use crate::support::execution::{execute_script, execute_script_buf_without_stack_limit};
    use bitcoin::ScriptBuf;

    const USEFUL_LIMB_LENGTHS: [u8; 2] = [4, 29];

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
            assert_eq!(
                bitcoin_script_stack::optimizer::optimize(script.clone()),
                script
            );
        }
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
