//! One-shot strict metric for the eight-item Ed25519 field-wire codec.
//!
//! Run with
//! `cargo run --locked --release --example ed25519_u5_packed_codec_benchmark`.

use bitcoin::{consensus::encode::serialize, script::Instruction, Witness};
use bitcoin_lab::{
    arithmetic::{
        bigint::bits::limb_to_le_bits,
        u31::u31_to_bits_with_width,
        u32::stack::{u32_compress, u32_uncompress},
    },
    fields::ed25519::{u5_balanced_table as field, u5_packed as packed},
    support::{execution::execute_raw_script_with_inputs_strict, script::ScriptCompilation},
};

fn scriptnum(value: i32) -> Vec<u8> {
    let mut bytes = [0u8; 8];
    let length = bitcoin::script::write_scriptint(&mut bytes, i64::from(value));
    bytes[..length].to_vec()
}

fn static_non_push_opcodes(script: &bitcoin::ScriptBuf) -> usize {
    script
        .instructions()
        .map(|instruction| instruction.expect("generated script must parse"))
        .filter(
            |instruction| matches!(instruction, Instruction::Op(opcode) if opcode.to_u8() > 0x60),
        )
        .count()
}

fn main() {
    // Maximum canonical packed payload: every high digit is 31 and digit zero
    // is 12. This exercises negative compressed words and the gap boundary.
    let mut digits = [31; field::FIELD_DIGIT_COUNT];
    digits[0] = 12;
    let value = field::value_from_field_digits(&digits);
    let packed_witness = packed::packed_value_witness_items(&value);
    let digit_witness = digits
        .iter()
        .rev()
        .map(|digit| scriptnum(*digit))
        .collect::<Vec<_>>();

    let decode = packed::decode(0).compile_with_policy();
    let preserving_decode = packed::decode_preserving(0).compile_with_policy();
    let fast_decode = packed::decode_fast(0).compile_with_policy();
    let fast_preserving_decode = packed::decode_fast_preserving(0).compile_with_policy();
    let encode = packed::encode_certified(0).compile_with_policy();
    let raw_encode = packed::encode_from_raw_digits(0).compile_with_policy();
    assert_eq!(decode.len(), packed::DECODE_SCRIPT_BYTES);
    assert_eq!(
        preserving_decode.len(),
        packed::PRESERVING_DECODE_SCRIPT_BYTES
    );
    assert_eq!(encode.len(), packed::ENCODE_CERTIFIED_SCRIPT_BYTES);
    assert_eq!(raw_encode.len(), packed::ENCODE_RAW_SCRIPT_BYTES);
    assert_eq!(fast_decode.len(), packed::FAST_DECODE_SCRIPT_BYTES);
    assert_eq!(
        fast_preserving_decode.len(),
        packed::FAST_PRESERVING_DECODE_SCRIPT_BYTES
    );

    let decoded = execute_raw_script_with_inputs_strict(decode.to_bytes(), packed_witness.clone());
    assert!(decoded.error.is_none(), "decode failed: {decoded}");
    assert_eq!(decoded.final_stack.len(), field::FIELD_DIGIT_COUNT);

    let preserving =
        execute_raw_script_with_inputs_strict(preserving_decode.to_bytes(), packed_witness.clone());
    assert!(
        preserving.error.is_none(),
        "preserving decode failed: {preserving}"
    );
    assert_eq!(
        preserving.final_stack.len(),
        packed::PACKED_WORD_COUNT + field::FIELD_DIGIT_COUNT
    );

    let fast_decoded =
        execute_raw_script_with_inputs_strict(fast_decode.to_bytes(), packed_witness.clone());
    assert!(
        fast_decoded.error.is_none(),
        "fast decode failed: {fast_decoded}"
    );
    assert_eq!(fast_decoded.final_stack.len(), field::FIELD_DIGIT_COUNT);

    let fast_preserving = execute_raw_script_with_inputs_strict(
        fast_preserving_decode.to_bytes(),
        packed_witness.clone(),
    );
    assert!(
        fast_preserving.error.is_none(),
        "fast preserving decode failed: {fast_preserving}"
    );
    assert_eq!(
        fast_preserving.final_stack.len(),
        packed::PACKED_WORD_COUNT + field::FIELD_DIGIT_COUNT
    );

    let encoded = execute_raw_script_with_inputs_strict(encode.to_bytes(), digit_witness.clone());
    assert!(encoded.error.is_none(), "encode failed: {encoded}");
    assert_eq!(encoded.final_stack.len(), packed::PACKED_WORD_COUNT);
    for (index, expected) in packed_witness.iter().enumerate() {
        assert_eq!(encoded.final_stack.get(index), *expected);
    }

    let raw_encoded =
        execute_raw_script_with_inputs_strict(raw_encode.to_bytes(), digit_witness.clone());
    assert!(
        raw_encoded.error.is_none(),
        "raw encode failed: {raw_encoded}"
    );

    println!("decode_locking_script_bytes={}", decode.len());
    println!(
        "preserving_decode_locking_script_bytes={}",
        preserving_decode.len()
    );
    println!("fast_decode_locking_script_bytes={}", fast_decode.len());
    println!(
        "fast_preserving_decode_locking_script_bytes={}",
        fast_preserving_decode.len()
    );
    println!("certified_encode_locking_script_bytes={}", encode.len());
    println!("raw_encode_locking_script_bytes={}", raw_encode.len());
    println!(
        "u32_uncompress_component_bytes={}",
        u32_uncompress().compile_with_policy().len()
    );
    println!(
        "u32_compress_component_bytes={}",
        u32_compress().compile_with_policy().len()
    );
    println!(
        "digit_to_bits_component_bytes={}",
        u31_to_bits_with_width(5).compile_with_policy().len()
    );
    println!(
        "u31_to_bits_component_bytes={}",
        u31_to_bits_with_width(31).compile_with_policy().len()
    );
    println!(
        "bigint_limb_to_bits_component_bytes={}",
        limb_to_le_bits(31).compile_with_policy().len()
    );
    println!(
        "decode_static_non_push_opcodes={}",
        static_non_push_opcodes(&decode)
    );
    println!(
        "preserving_decode_static_non_push_opcodes={}",
        static_non_push_opcodes(&preserving_decode)
    );
    println!(
        "fast_decode_static_non_push_opcodes={}",
        static_non_push_opcodes(&fast_decode)
    );
    println!(
        "fast_preserving_decode_static_non_push_opcodes={}",
        static_non_push_opcodes(&fast_preserving_decode)
    );
    println!(
        "certified_encode_static_non_push_opcodes={}",
        static_non_push_opcodes(&encode)
    );
    println!("incremental_hint_items={}", packed::CODEC_HINT_ITEM_COUNT);
    println!("packed_input_items={}", packed_witness.len());
    println!(
        "maximum_packed_witness_bytes={}",
        packed::MAX_PACKED_WITNESS_BYTES
    );
    println!(
        "packed_input_witness_bytes={}",
        serialize(&Witness::from_slice(&packed_witness)).len()
    );
    println!("expanded_output_items={}", field::FIELD_DIGIT_COUNT);
    println!(
        "decode_max_stack_items={}",
        decoded.stats.max_nb_stack_items
    );
    println!(
        "preserving_decode_max_stack_items={}",
        preserving.stats.max_nb_stack_items
    );
    println!(
        "fast_decode_max_stack_items={}",
        fast_decoded.stats.max_nb_stack_items
    );
    println!(
        "fast_preserving_decode_max_stack_items={}",
        fast_preserving.stats.max_nb_stack_items
    );
    println!(
        "encode_max_stack_items={}",
        encoded.stats.max_nb_stack_items
    );
    println!(
        "raw_encode_max_stack_items={}",
        raw_encoded.stats.max_nb_stack_items
    );
    assert_eq!(
        decoded.stats.max_nb_stack_items,
        packed::DECODE_STACK_ITEMS as usize
    );
    assert_eq!(
        preserving.stats.max_nb_stack_items,
        packed::PRESERVING_DECODE_STACK_ITEMS as usize
    );
    assert_eq!(
        fast_decoded.stats.max_nb_stack_items,
        packed::FAST_DECODE_STACK_ITEMS as usize
    );
    assert_eq!(
        fast_preserving.stats.max_nb_stack_items,
        packed::FAST_PRESERVING_DECODE_STACK_ITEMS as usize
    );
    assert_eq!(
        encoded.stats.max_nb_stack_items,
        packed::ENCODE_STACK_ITEMS as usize
    );
    println!("execution_samples=1_per_configuration");
    println!("compilation_policy=CompileOptions::ALL_under_32KiB_cutoff");
    println!("execution_class=unclassified");
    println!("context=tapscript,strict_1000_item_stack,bitcoin-scriptexec");
}
