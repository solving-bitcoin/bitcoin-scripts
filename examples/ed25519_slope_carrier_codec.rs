//! Signed-ScriptNum metadata carriers for the Ed25519 Montgomery slope chain.
//!
//! This focused example implements and strictly executes two codecs without
//! constructing a scalar multiplication:
//!
//! - a signed quotient item carries `32-w` certified metadata bits (the
//!   benchmark covers signed-20 through signed-23 slots); and
//! - the otherwise-zero bit 255 of a packed field carries one certified bit.
//!
//! For a `w`-bit signed quotient slot, let `bias = 2^(w-1)` and let `low`
//! contain the lower `31-w` metadata bits:
//!
//! ```text
//! payload = (low << w) + (q + bias)
//! carrier = payload                 when the metadata sign bit is zero
//! carrier = -(payload + 1)          when the metadata sign bit is one
//! ```
//!
//! Script first certifies a minimal at-most-four-byte ScriptNum, uses its sign
//! as the final metadata bit, then decomposes the nonnegative 31-bit payload.
//! The one absent four-byte code is `carrier = -2^31`. The proved slope-chain
//! quotient intervals never require it, even when every metadata bit is one.
//! For the current response schedule, eight packed-field padding bits join 505
//! q-metadata bits in a 513-bit stream. All eight padding bits occur inside the
//! response-side 512-bit transcript; the final q-metadata bit is the checked
//! zero surplus. The 16 challenge-side groups add enough q capacity for the
//! scalar without another padding channel.
//!
//! This is a transport codec, not a binding proof. The slope relation must
//! consume the recovered quotient, and the transcript/scalar consumer must
//! consume the recovered bits in the committed order. Likewise, clearing a
//! packed field's padding bit certifies only that bit; the wrapper below also
//! invokes the canonical packed-field decoder to certify the restored field.

use bitcoin::{consensus::encode::serialize, script::Instruction, Witness};
use bitcoin_lab::{
    fields::ed25519::{u5_balanced_table, u5_packed},
    support::{
        execution::execute_raw_script_with_inputs_strict,
        script::{script, Script, ScriptCompilation, MAX_OPTIMIZER_INPUT_BYTES},
    },
};
use num_bigint::BigUint;

const SIGNED23_Q_BITS: usize = 23;
const SIGNED22_Q_BITS: usize = 22;
const SIGNED21_Q_BITS: usize = 21;
const SIGNED20_Q_BITS: usize = 20;
const SIGNED23_METADATA_BITS: usize = 9;
const SIGNED22_METADATA_BITS: usize = 10;
const SIGNED21_METADATA_BITS: usize = 11;
const SIGNED20_METADATA_BITS: usize = 12;
const TRANSITIONS: usize = 44;
const FIRST_PREFIX_TRANSITIONS: usize = 28;
const Q_HINTS_PER_TRANSITION: usize = 2;
const TRACE_FIELDS_PER_TRANSITION: usize = 2;
const PACKED_WORDS_PER_FIELD: usize = 8;
const EXTRACTED_SCALAR_WORD_ITEMS: usize = 8;
const SCALAR_CARRIER_Q_ITEMS: usize = 29;

// Correlation-free hostile-input bounds reproduced by
// `ed25519_montgomery_slope_bounds`.
const SQUARE_Q_MIN: i32 = -3_150_640;
const SQUARE_Q_MAX: i32 = 3_360_683;
const FIRST_CONTINUITY_Q_MIN: i32 = -1_843_466;
const FIRST_CONTINUITY_Q_MAX: i32 = 1_843_466;
const CHAINED_CONTINUITY_Q_MIN: i32 = -3_686_931;
const CHAINED_CONTINUITY_Q_MAX: i32 = 3_686_931;
// Narrower all-u3 alternatives are codec fixtures, not the active kernel
// profile. The direct staggered-linear kernel uses the wider bounds above.
const ALL_U3_FIRST_CONTINUITY_Q_MIN: i32 = -287_514;
const ALL_U3_FIRST_CONTINUITY_Q_MAX: i32 = 287_514;
const ALL_U3_CHAINED_CONTINUITY_Q_MIN: i32 = -575_027;
const ALL_U3_CHAINED_CONTINUITY_Q_MAX: i32 = 575_027;

fn scriptnum_item(value: i64) -> Vec<u8> {
    let mut bytes = [0u8; 8];
    let length = bitcoin::script::write_scriptint(&mut bytes, value);
    bytes[..length].to_vec()
}

fn policy_precompiled(fragment: Script, name: &'static str) -> Script {
    Script::new(name).push_script(fragment.compile_with_policy())
}

/// Decode one signed carrier.
///
/// Before: `carrier`.
/// After: `q | metadata_bit[0] | ... | metadata_bit[31-q_bits]`, with the
/// highest metadata bit nearest the top. The output bits are literal zero or
/// one ScriptNums.
fn decode_carrier_semantic(q_bits: usize) -> Script {
    assert!((1..31).contains(&q_bits));
    let low_metadata_bits = 31 - q_bits;
    let bias = 1u32 << (q_bits - 1);

    script! {
        // Arithmetic ScriptNums are limited to four bytes. Checking the raw
        // length first rejects the sole missing carrier code (-2^31) without
        // ever feeding it into an arithmetic opcode.
        OP_SIZE 5 OP_LESSTHAN OP_VERIFY

        // Normalize the at-most-four-byte number and compare its raw bytes.
        // This rejects negative zero and redundant sign bytes independently
        // of the execution flags' MINIMALDATA setting.
        OP_DUP OP_DUP 0 OP_ADD OP_EQUALVERIFY

        // Retain the sign as the highest metadata bit. For a negative carrier,
        // recover payload from c = -(payload + 1). Every intermediate is at
        // most 2^31-1 because -2^31 was rejected above.
        OP_DUP 0 OP_LESSTHAN
        OP_DUP OP_TOALTSTACK
        OP_IF
            OP_NEGATE OP_1SUB
        OP_ENDIF

        // Extract payload bits 30 down through q_bits. Parking them on
        // altstack makes restoration emit metadata bit zero first.
        for bit in (q_bits..31).rev() {
            { 1u32 << bit }
            OP_2DUP OP_GREATERTHANOREQUAL
            OP_IF
                OP_SUB 1
            OP_ELSE
                OP_DROP 0
            OP_ENDIF
            OP_TOALTSTACK
        }

        { bias } OP_SUB
        for _ in 0..low_metadata_bits { OP_FROMALTSTACK }
        OP_FROMALTSTACK
    }
}

/// Compact decoder with the same hostile-input checks as
/// [`decode_carrier_semantic`].
///
/// Before: `carrier`.
/// After: `q | metadata_chunk`. The chunk is an unsigned `32-q_bits` bit
/// integer instead of one stack item per bit.
pub(crate) fn decode_carrier_compact_semantic(q_bits: usize) -> Script {
    assert!((1..31).contains(&q_bits));
    let low_metadata_bits = 31 - q_bits;
    let bias = 1u32 << (q_bits - 1);

    script! {
        OP_SIZE 5 OP_LESSTHAN OP_VERIFY
        OP_DUP OP_DUP 0 OP_ADD OP_EQUALVERIFY
        OP_DUP 0 OP_LESSTHAN
        OP_DUP OP_TOALTSTACK
        OP_IF
            OP_NEGATE OP_1SUB
        OP_ENDIF

        // State is remainder | metadata-prefix. Reading payload bits from
        // high to low lets one Horner accumulator replace all bit outputs.
        0 OP_SWAP
        for bit in (q_bits..31).rev() {
            { 1u32 << bit }
            OP_2DUP OP_GREATERTHANOREQUAL
            OP_IF
                OP_SUB 1
            OP_ELSE
                OP_DROP 0
            OP_ENDIF
            // accumulator = 2*accumulator + extracted_bit.
            OP_ROT OP_DUP OP_ADD OP_ADD OP_SWAP
        }

        // remainder | metadata_low -> q | metadata_low.
        { bias } OP_SUB OP_SWAP
        OP_FROMALTSTACK
        OP_IF
            { 1u32 << low_metadata_bits } OP_ADD
        OP_ENDIF
    }
}

/// Combine two already-certified metadata chunks and zero, one, or two
/// already-certified padding bits into one unsigned chunk.
///
/// Before: `q_curve | q_continuity | curve_meta | continuity_meta |
/// padding_bit[0] | padding_bit[1]` (the padding suffix has `padding_bits`
/// items). After: `q_curve | q_continuity | combined_chunk`.
fn combine_metadata_chunks_semantic(
    curve_metadata_bits: usize,
    continuity_metadata_bits: usize,
    padding_bits: usize,
) -> Script {
    assert!((1..=12).contains(&curve_metadata_bits));
    assert!((1..=12).contains(&continuity_metadata_bits));
    assert!(padding_bits <= 2);
    assert!(curve_metadata_bits + continuity_metadata_bits + padding_bits <= 21);

    script! {
        if padding_bits == 2 {
            // padding chunk = bit0 + 2*bit1.
            OP_DUP OP_ADD OP_ADD
        }
        if padding_bits != 0 {
            for _ in 0..continuity_metadata_bits { OP_DUP OP_ADD }
            OP_ADD
        }
        for _ in 0..curve_metadata_bits { OP_DUP OP_ADD }
        OP_ADD
    }
}

/// Decode an active relation pair directly to two q values and one compact
/// metadata chunk. Padding bits, if present, are certified outputs of the
/// field-padding decoder and are parked while both signed carriers decode.
///
/// Before: `continuity_carrier | curve_carrier | padding_bit[0] |
/// padding_bit[1]`. After: `q_curve | q_continuity | combined_chunk`.
pub(crate) fn decode_pair_to_chunk_semantic(
    curve_q_bits: usize,
    continuity_q_bits: usize,
    padding_bits: usize,
) -> Script {
    let curve_metadata_bits = 32 - curve_q_bits;
    let continuity_metadata_bits = 32 - continuity_q_bits;
    script! {
        for _ in 0..padding_bits { OP_TOALTSTACK }

        { decode_carrier_compact_semantic(curve_q_bits) }
        2 OP_ROLL
        { decode_carrier_compact_semantic(continuity_q_bits) }

        // q_curve | curve_meta | q_continuity | continuity_meta
        // -> q_curve | q_continuity | curve_meta | continuity_meta.
        2 OP_ROLL OP_SWAP
        for _ in 0..padding_bits { OP_FROMALTSTACK }
        { combine_metadata_chunks_semantic(
            curve_metadata_bits,
            continuity_metadata_bits,
            padding_bits,
        ) }
    }
}

/// Host encoder shared by the focused carrier probes and honest-witness
/// generator. `None` is the unique unavailable `-2^31` ScriptNum code.
pub(crate) fn encode_carrier(metadata: u16, q: i32, q_bits: usize) -> Option<i64> {
    assert!((1..31).contains(&q_bits));
    let metadata_bits = 32 - q_bits;
    assert!(u32::from(metadata) < (1u32 << metadata_bits));
    let bias = 1i64 << (q_bits - 1);
    assert!((-bias..bias).contains(&i64::from(q)));

    let low_metadata_mask = (1u16 << (metadata_bits - 1)) - 1;
    let sign = metadata >> (metadata_bits - 1);
    let low = metadata & low_metadata_mask;
    let payload = (i64::from(low) << q_bits) + i64::from(q) + bias;
    debug_assert!((0..(1i64 << 31)).contains(&payload));
    let carrier = if sign == 0 { payload } else { -(payload + 1) };
    (carrier != -(1i64 << 31)).then_some(carrier)
}

fn metadata_bit(metadata: u16, bit: usize) -> u32 {
    u32::from((metadata >> bit) & 1)
}

fn carrier_checker(q_bits: usize, metadata: u16, q: i32) -> bitcoin::ScriptBuf {
    let metadata_bits = 32 - q_bits;
    script! {
        { policy_precompiled(decode_carrier_semantic(q_bits), "signed quotient carrier decoder") }
        for bit in (0..metadata_bits).rev() {
            { metadata_bit(metadata, bit) } OP_NUMEQUALVERIFY
        }
        { q } OP_NUMEQUALVERIFY
        OP_1
    }
    .compile_with_policy()
}

fn execute_carrier_fixture(q_bits: usize, metadata: u16, q: i32) -> usize {
    let carrier = encode_carrier(metadata, q, q_bits).expect("fixture carrier must be encodable");
    let execution = execute_raw_script_with_inputs_strict(
        carrier_checker(q_bits, metadata, q).to_bytes(),
        vec![scriptnum_item(carrier)],
    );
    assert!(
        execution.error.is_none(),
        "q_bits={q_bits}, metadata={metadata:#x}, q={q}: {execution}"
    );
    assert_eq!(execution.final_stack.len(), 1);
    execution.stats.max_nb_stack_items
}

fn compact_carrier_checker(q_bits: usize, metadata: u16, q: i32) -> bitcoin::ScriptBuf {
    script! {
        { policy_precompiled(
            decode_carrier_compact_semantic(q_bits),
            "compact signed quotient carrier decoder",
        ) }
        { u32::from(metadata) } OP_NUMEQUALVERIFY
        { q } OP_NUMEQUALVERIFY
        OP_1
    }
    .compile_with_policy()
}

fn execute_compact_carrier_fixture(q_bits: usize, metadata: u16, q: i32) -> usize {
    let carrier = encode_carrier(metadata, q, q_bits).expect("fixture carrier must be encodable");
    let execution = execute_raw_script_with_inputs_strict(
        compact_carrier_checker(q_bits, metadata, q).to_bytes(),
        vec![scriptnum_item(carrier)],
    );
    assert!(
        execution.error.is_none(),
        "compact q_bits={q_bits}, metadata={metadata:#x}, q={q}: {execution}"
    );
    assert_eq!(execution.final_stack.len(), 1);
    execution.stats.max_nb_stack_items
}

fn pair_chunk(
    curve_metadata: u16,
    continuity_metadata: u16,
    curve_metadata_bits: usize,
    continuity_metadata_bits: usize,
    padding: &[u32],
) -> u32 {
    assert!(padding.len() <= 2);
    let padding_chunk = padding
        .iter()
        .copied()
        .enumerate()
        .fold(0u32, |chunk, (bit, value)| {
            assert!(value <= 1);
            chunk | (value << bit)
        });
    u32::from(curve_metadata)
        | (u32::from(continuity_metadata) << curve_metadata_bits)
        | (padding_chunk << (curve_metadata_bits + continuity_metadata_bits))
}

fn execute_pair_fixture(
    curve_q_bits: usize,
    continuity_q_bits: usize,
    curve_metadata: u16,
    continuity_metadata: u16,
    q_curve: i32,
    q_continuity: i32,
    padding: &[u32],
) -> (usize, usize) {
    let curve_metadata_bits = 32 - curve_q_bits;
    let continuity_metadata_bits = 32 - continuity_q_bits;
    let expected_chunk = pair_chunk(
        curve_metadata,
        continuity_metadata,
        curve_metadata_bits,
        continuity_metadata_bits,
        padding,
    );
    assert!(expected_chunk < (1u32 << 21));
    let script = script! {
        { policy_precompiled(
            decode_pair_to_chunk_semantic(curve_q_bits, continuity_q_bits, padding.len()),
            "compact quotient-pair carrier decoder",
        ) }
        { expected_chunk } OP_NUMEQUALVERIFY
        { q_continuity } OP_NUMEQUALVERIFY
        { q_curve } OP_NUMEQUALVERIFY
        OP_1
    }
    .compile_with_policy();
    let mut witness = vec![
        scriptnum_item(
            encode_carrier(continuity_metadata, q_continuity, continuity_q_bits)
                .expect("continuity carrier is encodable"),
        ),
        scriptnum_item(
            encode_carrier(curve_metadata, q_curve, curve_q_bits)
                .expect("curve carrier is encodable"),
        ),
    ];
    witness.extend(padding.iter().map(|bit| scriptnum_item(i64::from(*bit))));
    let execution = execute_raw_script_with_inputs_strict(script.to_bytes(), witness);
    assert!(execution.error.is_none(), "compact pair: {execution}");
    assert_eq!(execution.final_stack.len(), 1);
    (execution.stats.max_nb_stack_items, expected_chunk as usize)
}

fn assert_carrier_rejected(q_bits: usize, item: Vec<u8>, description: &str) {
    let script = script! {
        { policy_precompiled(decode_carrier_semantic(q_bits), "rejecting carrier decoder") }
        OP_1
    }
    .compile_with_policy();
    let execution = execute_raw_script_with_inputs_strict(script.to_bytes(), vec![item]);
    assert!(
        execution.error.is_some(),
        "accepted {description}: {execution}"
    );
}

/// Extract bit 31 from one compressed-u32 word and clear it.
///
/// Before: `signed_compressed_word`.
/// After: `low31 | metadata_bit`, with the bit nearest the top. The exact
/// canonical five-byte -2^31 sentinel is handled without arithmetic.
pub(crate) fn clear_packed_field_padding_bit_semantic() -> Script {
    script! {
        OP_SIZE 5 OP_NUMEQUAL
        OP_IF
            OP_DUP { -2_147_483_648i64 } OP_EQUALVERIFY
            OP_DROP 0 1
        OP_ELSE
            // Reject raw aliases before interpreting the ScriptNum sign.
            OP_DUP OP_DUP 0 OP_ADD OP_EQUALVERIFY
            OP_DUP 0 OP_LESSTHAN
            OP_IF
                // low31 = signed_word + 2^31. Split the constant so no
                // arithmetic operand is the five-byte value +2^31.
                { 0x7fff_ffffu32 } OP_ADD OP_1ADD
                1
            OP_ELSE
                0
            OP_ENDIF
        OP_ENDIF
    }
}

fn padding_checker(expected_low31: u32, expected_bit: u32) -> bitcoin::ScriptBuf {
    script! {
        { policy_precompiled(clear_packed_field_padding_bit_semantic(), "padding carrier decoder") }
        { expected_bit } OP_NUMEQUALVERIFY
        { expected_low31 } OP_NUMEQUALVERIFY
        OP_1
    }
    .compile_with_policy()
}

fn execute_padding_fixture(word: i64, expected_low31: u32, expected_bit: u32) -> usize {
    let execution = execute_raw_script_with_inputs_strict(
        padding_checker(expected_low31, expected_bit).to_bytes(),
        vec![scriptnum_item(word)],
    );
    assert!(execution.error.is_none(), "word={word}: {execution}");
    assert_eq!(execution.final_stack.len(), 1);
    execution.stats.max_nb_stack_items
}

/// Clear word seven's metadata bit, restore public packed-word order, certify
/// all eight packed words and the canonical field interval, then append the
/// recovered bit.
///
/// Before: `word[7]_carrier | word[6] | ... | word[0]`.
/// After: `digit[50] | ... | digit[0] | metadata_bit`.
fn decode_padded_field_semantic() -> Script {
    script! {
        7 OP_ROLL
        { clear_packed_field_padding_bit_semantic() }
        OP_TOALTSTACK

        // A fixed-depth left rotation moves restored word seven back below
        // words six through zero.
        for _ in 0..7 { 7 OP_ROLL }

        // Account for the metadata bit already live on altstack. The canonical
        // decoder rejects aliases, the padding bit, and the 19-value field gap.
        { u5_packed::decode(1) }
        OP_FROMALTSTACK
    }
}

fn padded_word7(word7: u32, metadata_bit: u32) -> i64 {
    assert!(word7 < (1u32 << 31));
    assert!(metadata_bit <= 1);
    i64::from((word7 | (metadata_bit << 31)) as i32)
}

fn execute_full_field_fixture(value: &BigUint, metadata_bit_value: u32) -> (usize, usize) {
    let digits = u5_balanced_table::field_digits(value);
    let words = u5_packed::packed_words_from_digits(&digits);
    let mut witness = u5_packed::packed_value_witness_items(value);
    witness[0] = scriptnum_item(padded_word7(words[7], metadata_bit_value));
    let witness_bytes = serialize(&Witness::from_slice(&witness)).len();

    let script = script! {
        { policy_precompiled(decode_padded_field_semantic(), "canonical padded-field decoder") }
        { metadata_bit_value } OP_NUMEQUALVERIFY
        for digit in digits.iter() {
            { *digit } OP_NUMEQUALVERIFY
        }
        OP_1
    }
    .compile_with_policy();
    let execution = execute_raw_script_with_inputs_strict(script.to_bytes(), witness);
    assert!(
        execution.error.is_none(),
        "full padded field bit={metadata_bit_value}: {execution}"
    );
    assert_eq!(execution.final_stack.len(), 1);
    (execution.stats.max_nb_stack_items, witness_bytes)
}

fn raw_fragment_len(fragment: Script) -> usize {
    // Force the centralized compilation policy's no-optimizer branch, then
    // divide the byte-identical concatenation. No upstream compile API is
    // called directly.
    const COPIES: usize = 2_048;
    let repeated = script! {
        for _ in 0..COPIES { { fragment.clone() } }
    }
    .compile_with_policy();
    assert!(repeated.len() > MAX_OPTIMIZER_INPUT_BYTES);
    assert_eq!(repeated.len() % COPIES, 0);
    repeated.len() / COPIES
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
    assert_eq!(SIGNED23_METADATA_BITS, 32 - SIGNED23_Q_BITS);
    assert_eq!(SIGNED22_METADATA_BITS, 32 - SIGNED22_Q_BITS);
    assert_eq!(SIGNED21_METADATA_BITS, 32 - SIGNED21_Q_BITS);
    assert_eq!(SIGNED20_METADATA_BITS, 32 - SIGNED20_Q_BITS);

    // Both signs, both signed-slot boundaries, all-one low metadata, and the
    // actual proved quotient extrema are exercised under the strict stack
    // limit. The sole unencodable code is tested separately below.
    let signed23_fixtures = [
        (0x000u16, -(1 << 22)),
        (0x0ff, (1 << 22) - 1),
        (0x100, -(1 << 22)),
        (0x100, (1 << 22) - 1),
        (0x1a5, -17),
        (0x1ff, SQUARE_Q_MIN),
        (0x1ff, SQUARE_Q_MAX),
        (0x1ff, CHAINED_CONTINUITY_Q_MIN),
        (0x1ff, CHAINED_CONTINUITY_Q_MAX),
        (0x1ff, (1 << 22) - 2),
    ];
    let signed22_fixtures = [
        (0x000u16, -(1 << 21)),
        (0x1ff, (1 << 21) - 1),
        (0x200, -(1 << 21)),
        (0x200, (1 << 21) - 1),
        (0x3ff, FIRST_CONTINUITY_Q_MIN),
        (0x3ff, FIRST_CONTINUITY_Q_MAX),
        (0x3ff, (1 << 21) - 2),
    ];
    let signed21_fixtures = [
        (0x000u16, -(1 << 20)),
        (0x3ff, (1 << 20) - 1),
        (0x400, -(1 << 20)),
        (0x400, (1 << 20) - 1),
        (0x7ff, ALL_U3_CHAINED_CONTINUITY_Q_MIN),
        (0x7ff, ALL_U3_CHAINED_CONTINUITY_Q_MAX),
        (0x7ff, (1 << 20) - 2),
    ];
    let signed20_fixtures = [
        (0x000u16, -(1 << 19)),
        (0x7ff, (1 << 19) - 1),
        (0x800, -(1 << 19)),
        (0x800, (1 << 19) - 1),
        (0xfff, ALL_U3_FIRST_CONTINUITY_Q_MIN),
        (0xfff, ALL_U3_FIRST_CONTINUITY_Q_MAX),
        (0xfff, (1 << 19) - 2),
    ];
    let signed23_peak = signed23_fixtures
        .into_iter()
        .map(|(metadata, q)| execute_carrier_fixture(SIGNED23_Q_BITS, metadata, q))
        .max()
        .unwrap();
    let signed22_peak = signed22_fixtures
        .into_iter()
        .map(|(metadata, q)| execute_carrier_fixture(SIGNED22_Q_BITS, metadata, q))
        .max()
        .unwrap();
    let signed21_peak = signed21_fixtures
        .into_iter()
        .map(|(metadata, q)| execute_carrier_fixture(SIGNED21_Q_BITS, metadata, q))
        .max()
        .unwrap();
    let signed20_peak = signed20_fixtures
        .into_iter()
        .map(|(metadata, q)| execute_carrier_fixture(SIGNED20_Q_BITS, metadata, q))
        .max()
        .unwrap();
    let signed23_compact_peak = signed23_fixtures
        .iter()
        .copied()
        .map(|(metadata, q)| execute_compact_carrier_fixture(SIGNED23_Q_BITS, metadata, q))
        .max()
        .unwrap();
    let signed22_compact_peak = signed22_fixtures
        .iter()
        .copied()
        .map(|(metadata, q)| execute_compact_carrier_fixture(SIGNED22_Q_BITS, metadata, q))
        .max()
        .unwrap();
    let signed21_compact_peak = signed21_fixtures
        .iter()
        .copied()
        .map(|(metadata, q)| execute_compact_carrier_fixture(SIGNED21_Q_BITS, metadata, q))
        .max()
        .unwrap();
    let signed20_compact_peak = signed20_fixtures
        .iter()
        .copied()
        .map(|(metadata, q)| execute_compact_carrier_fixture(SIGNED20_Q_BITS, metadata, q))
        .max()
        .unwrap();

    let (first_pair_two_padding_peak, first_pair_max_chunk) = execute_pair_fixture(
        SIGNED23_Q_BITS,
        SIGNED22_Q_BITS,
        0x1ff,
        0x3ff,
        SQUARE_Q_MAX,
        FIRST_CONTINUITY_Q_MAX,
        &[1, 1],
    );
    let (regular_pair_two_padding_peak, regular_pair_max_chunk) = execute_pair_fixture(
        SIGNED23_Q_BITS,
        SIGNED23_Q_BITS,
        0x1ff,
        0x1ff,
        SQUARE_Q_MIN,
        CHAINED_CONTINUITY_Q_MAX,
        &[1, 1],
    );
    let (regular_pair_no_padding_peak, _) = execute_pair_fixture(
        SIGNED23_Q_BITS,
        SIGNED23_Q_BITS,
        0x155,
        0x0aa,
        SQUARE_Q_MIN,
        CHAINED_CONTINUITY_Q_MIN,
        &[],
    );
    assert_eq!(first_pair_max_chunk, (1usize << 21) - 1);
    assert_eq!(regular_pair_max_chunk, (1usize << 20) - 1);

    assert_eq!(encode_carrier(0x1ff, (1 << 22) - 1, SIGNED23_Q_BITS), None);
    assert_eq!(encode_carrier(0x3ff, (1 << 21) - 1, SIGNED22_Q_BITS), None);
    assert_eq!(encode_carrier(0x7ff, (1 << 20) - 1, SIGNED21_Q_BITS), None);
    assert_eq!(encode_carrier(0xfff, (1 << 19) - 1, SIGNED20_Q_BITS), None);
    assert_carrier_rejected(
        SIGNED23_Q_BITS,
        scriptnum_item(-(1i64 << 31)),
        "five-byte -2^31 missing carrier code",
    );
    assert_carrier_rejected(SIGNED23_Q_BITS, vec![0x80], "negative-zero carrier alias");
    assert_carrier_rejected(
        SIGNED23_Q_BITS,
        vec![1, 0],
        "redundant-positive-sign carrier alias",
    );

    let padding_peak = [
        (0i64, 0u32, 0u32),
        (i64::from(i32::MAX), 0x7fff_ffff, 0),
        (-1, 0x7fff_ffff, 1),
        (-2_147_483_647, 1, 1),
        (-2_147_483_648, 0, 1),
    ]
    .into_iter()
    .map(|(word, low31, bit)| execute_padding_fixture(word, low31, bit))
    .max()
    .unwrap();

    let padding_reject_script = script! {
        { policy_precompiled(clear_packed_field_padding_bit_semantic(), "rejecting padding decoder") }
        OP_1
    }
    .compile_with_policy();
    for (item, description) in [
        (vec![0x80], "negative-zero packed word"),
        (vec![1, 0], "redundant-positive-sign packed word"),
        (vec![0, 0, 0, 0, 1], "non-sentinel five-byte packed word"),
    ] {
        let execution =
            execute_raw_script_with_inputs_strict(padding_reject_script.to_bytes(), vec![item]);
        assert!(
            execution.error.is_some(),
            "accepted {description}: {execution}"
        );
    }

    let p = u5_balanced_table::modulus();
    let fixture = BigUint::parse_bytes(
        b"123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        16,
    )
    .unwrap()
        % p;
    let (field_peak_zero, field_witness_zero) = execute_full_field_fixture(&fixture, 0);
    let (field_peak_one, field_witness_one) = execute_full_field_fixture(&fixture, 1);

    let signed23_decoder = decode_carrier_semantic(SIGNED23_Q_BITS);
    let signed22_decoder = decode_carrier_semantic(SIGNED22_Q_BITS);
    let signed21_decoder = decode_carrier_semantic(SIGNED21_Q_BITS);
    let signed20_decoder = decode_carrier_semantic(SIGNED20_Q_BITS);
    let padding_decoder = clear_packed_field_padding_bit_semantic();
    let signed23_compact_decoder = decode_carrier_compact_semantic(SIGNED23_Q_BITS);
    let signed22_compact_decoder = decode_carrier_compact_semantic(SIGNED22_Q_BITS);
    let signed21_compact_decoder = decode_carrier_compact_semantic(SIGNED21_Q_BITS);
    let signed20_compact_decoder = decode_carrier_compact_semantic(SIGNED20_Q_BITS);
    let first_pair_two_padding =
        decode_pair_to_chunk_semantic(SIGNED23_Q_BITS, SIGNED22_Q_BITS, 2).compile_with_policy();
    let regular_pair_two_padding =
        decode_pair_to_chunk_semantic(SIGNED23_Q_BITS, SIGNED23_Q_BITS, 2).compile_with_policy();
    let regular_pair_no_padding =
        decode_pair_to_chunk_semantic(SIGNED23_Q_BITS, SIGNED23_Q_BITS, 0).compile_with_policy();
    let field_decoder = decode_padded_field_semantic().compile_with_policy();
    let signed23_compiled = signed23_decoder.clone().compile_with_policy();
    let signed22_compiled = signed22_decoder.clone().compile_with_policy();
    let signed21_compiled = signed21_decoder.clone().compile_with_policy();
    let signed20_compiled = signed20_decoder.clone().compile_with_policy();
    let signed23_compact_compiled = signed23_compact_decoder.clone().compile_with_policy();
    let signed22_compact_compiled = signed22_compact_decoder.clone().compile_with_policy();
    let signed21_compact_compiled = signed21_compact_decoder.clone().compile_with_policy();
    let signed20_compact_compiled = signed20_compact_decoder.clone().compile_with_policy();
    let padding_compiled = padding_decoder.clone().compile_with_policy();

    let first_prefix_q_hints = FIRST_PREFIX_TRANSITIONS * Q_HINTS_PER_TRANSITION;
    let complete_q_hints = TRANSITIONS * Q_HINTS_PER_TRANSITION;
    // Active staggered-linear-kernel quotient profile: every curve and regular
    // continuity relation is signed 23; only the first continuity relation is
    // signed 22.
    let first_prefix_q_capacity = SIGNED23_METADATA_BITS
        + SIGNED22_METADATA_BITS
        + (first_prefix_q_hints - 2) * SIGNED23_METADATA_BITS;
    let complete_q_capacity = SIGNED23_METADATA_BITS
        + SIGNED22_METADATA_BITS
        + (complete_q_hints - 2) * SIGNED23_METADATA_BITS;
    let transcript_bits = 512usize;
    let padding_bits_needed_for_transcript = transcript_bits - first_prefix_q_capacity;
    let transcript_probe_padding_fields = 8usize;
    let trace_fields = TRANSITIONS * TRACE_FIELDS_PER_TRANSITION;
    let trace_data_items = trace_fields * PACKED_WORDS_PER_FIELD;
    let complete_entry_items = trace_data_items + complete_q_hints;
    let transcript_plus_scalar_bits = 765usize;
    let complete_q_headroom_over_payload = complete_q_capacity - transcript_plus_scalar_bits;
    let scalar_carrier_capacity = SCALAR_CARRIER_Q_ITEMS * SIGNED23_METADATA_BITS;
    let live_items_after_scalar_extraction = complete_entry_items + EXTRACTED_SCALAR_WORD_ITEMS;
    // During streaming, at most seven finished words and one partial word are
    // live. A compact decoder peaks five items above its existing one-item
    // carrier. Deep-roll constants do not coexist with that decoder scratch.
    let scalar_streaming_transient_upper_bound =
        live_items_after_scalar_extraction + signed23_compact_peak - 1;

    assert_eq!(first_prefix_q_hints, 56);
    assert_eq!(first_prefix_q_capacity, 505);
    assert_eq!(padding_bits_needed_for_transcript, 7);
    assert_eq!(
        first_prefix_q_capacity + transcript_probe_padding_fields,
        513
    );
    assert_eq!(complete_q_hints, 88);
    assert_eq!(complete_q_capacity, 793);
    assert_eq!(complete_q_headroom_over_payload, 28);
    assert_eq!(scalar_carrier_capacity, 261);
    assert_eq!(trace_data_items, 704);
    assert_eq!(complete_entry_items, 792);
    assert_eq!(live_items_after_scalar_extraction, 800);
    assert_eq!(scalar_streaming_transient_upper_bound, 805);

    let maximum_signed23_carrier_witness_bytes =
        serialize(&Witness::from_slice(&[scriptnum_item(
            encode_carrier(0x0ff, (1 << 22) - 1, SIGNED23_Q_BITS).unwrap(),
        )]))
        .len();
    let maximum_direct_signed23_q_witness_bytes =
        serialize(&Witness::from_slice(&[scriptnum_item((1 << 22) - 1)])).len();
    let zero_q_maximum_carrier = encode_carrier(0x0ff, 0, SIGNED23_Q_BITS).unwrap();
    let maximum_same_q_incremental_payload_bytes =
        scriptnum_item(zero_q_maximum_carrier).len() - scriptnum_item(0).len();
    let first_prefix_carrier_witness_upper_bound = 1 + first_prefix_q_hints * (1 + 4);
    let complete_carrier_witness_upper_bound = 1 + complete_q_hints * (1 + 4);
    let first_prefix_same_q_payload_overhead_upper_bound =
        first_prefix_q_hints * maximum_same_q_incremental_payload_bytes;
    let complete_same_q_payload_overhead_upper_bound =
        complete_q_hints * maximum_same_q_incremental_payload_bytes;
    assert_eq!(maximum_same_q_incremental_payload_bytes, 4);

    println!("model=ed25519_montgomery_slope_carrier_codec");
    println!("evidence=locally-reproduced");
    println!("execution_class=unclassified");
    println!("context=tapscript,strict_1000_item_stack,bitcoin-scriptexec");
    println!("long_scalar_or_hash_execution=false");
    println!("schedule_transitions={TRANSITIONS}");
    println!("active_q_width_profile=curve_signed23,first_continuity_signed22,regular_continuity_signed23");
    println!("curve_q_interval=[{SQUARE_Q_MIN},{SQUARE_Q_MAX}]");
    println!("first_continuity_q_interval=[{FIRST_CONTINUITY_Q_MIN},{FIRST_CONTINUITY_Q_MAX}]");
    println!(
        "regular_continuity_q_interval=[{CHAINED_CONTINUITY_Q_MIN},{CHAINED_CONTINUITY_Q_MAX}]"
    );
    println!("signed23_formula=payload=(meta_low8<<23)+(q+2^22);sign_bit_selects_payload_or_-(payload+1)");
    println!("signed23_input_items=1");
    println!("signed23_output_items=10");
    println!("signed23_logical_hint_items_per_carrier=1");
    println!("signed23_incremental_hint_items=0");
    println!("signed23_incremental_data_items=0");
    println!("signed23_metadata_bits=9");
    println!(
        "signed23_decoder_raw_bytes={}",
        raw_fragment_len(signed23_decoder)
    );
    println!("signed23_decoder_policy_bytes={}", signed23_compiled.len());
    println!(
        "signed23_decoder_static_non_push_opcodes={}",
        static_non_push_opcodes(&signed23_compiled)
    );
    println!("signed23_strict_combined_stack_peak={signed23_peak}");
    println!("signed23_maximum_standalone_carrier_witness_bytes={maximum_signed23_carrier_witness_bytes}");
    println!("signed23_maximum_standalone_direct_q_witness_bytes={maximum_direct_signed23_q_witness_bytes}");
    println!("signed23_maximum_carrier_payload_bytes=4");
    println!("signed23_maximum_direct_q_payload_bytes=3");
    println!(
        "signed23_maximum_same_q_incremental_payload_bytes_per_item={maximum_same_q_incremental_payload_bytes}"
    );
    println!("signed22_input_items=1");
    println!("signed22_output_items=11");
    println!("signed22_logical_hint_items_per_carrier=1");
    println!("signed22_incremental_hint_items=0");
    println!("signed22_incremental_data_items=0");
    println!("signed22_metadata_bits=10");
    println!(
        "signed22_decoder_raw_bytes={}",
        raw_fragment_len(signed22_decoder)
    );
    println!("signed22_decoder_policy_bytes={}", signed22_compiled.len());
    println!(
        "signed22_decoder_static_non_push_opcodes={}",
        static_non_push_opcodes(&signed22_compiled)
    );
    println!("signed22_strict_combined_stack_peak={signed22_peak}");
    println!("signed21_input_items=1");
    println!("signed21_output_items=12");
    println!("signed21_logical_hint_items_per_carrier=1");
    println!("signed21_incremental_hint_items=0");
    println!("signed21_incremental_data_items=0");
    println!("signed21_metadata_bits=11");
    println!(
        "signed21_decoder_raw_bytes={}",
        raw_fragment_len(signed21_decoder)
    );
    println!("signed21_decoder_policy_bytes={}", signed21_compiled.len());
    println!(
        "signed21_decoder_static_non_push_opcodes={}",
        static_non_push_opcodes(&signed21_compiled)
    );
    println!("signed21_strict_combined_stack_peak={signed21_peak}");
    println!("signed20_input_items=1");
    println!("signed20_output_items=13");
    println!("signed20_logical_hint_items_per_carrier=1");
    println!("signed20_incremental_hint_items=0");
    println!("signed20_incremental_data_items=0");
    println!("signed20_metadata_bits=12");
    println!(
        "signed20_decoder_raw_bytes={}",
        raw_fragment_len(signed20_decoder)
    );
    println!("signed20_decoder_policy_bytes={}", signed20_compiled.len());
    println!(
        "signed20_decoder_static_non_push_opcodes={}",
        static_non_push_opcodes(&signed20_compiled)
    );
    println!("signed20_strict_combined_stack_peak={signed20_peak}");
    println!("compact_signed23_input_items=1");
    println!("compact_signed23_output_items=2");
    println!("compact_signed23_metadata_chunk_bits=9");
    println!(
        "compact_signed23_decoder_raw_bytes={}",
        raw_fragment_len(signed23_compact_decoder)
    );
    println!(
        "compact_signed23_decoder_policy_bytes={}",
        signed23_compact_compiled.len()
    );
    println!(
        "compact_signed23_decoder_static_non_push_opcodes={}",
        static_non_push_opcodes(&signed23_compact_compiled)
    );
    println!("compact_signed23_strict_combined_stack_peak={signed23_compact_peak}");
    println!("compact_signed22_input_items=1");
    println!("compact_signed22_output_items=2");
    println!("compact_signed22_metadata_chunk_bits=10");
    println!(
        "compact_signed22_decoder_raw_bytes={}",
        raw_fragment_len(signed22_compact_decoder)
    );
    println!(
        "compact_signed22_decoder_policy_bytes={}",
        signed22_compact_compiled.len()
    );
    println!(
        "compact_signed22_decoder_static_non_push_opcodes={}",
        static_non_push_opcodes(&signed22_compact_compiled)
    );
    println!("compact_signed22_strict_combined_stack_peak={signed22_compact_peak}");
    println!("compact_signed21_input_items=1");
    println!("compact_signed21_output_items=2");
    println!("compact_signed21_metadata_chunk_bits=11");
    println!(
        "compact_signed21_decoder_raw_bytes={}",
        raw_fragment_len(signed21_compact_decoder)
    );
    println!(
        "compact_signed21_decoder_policy_bytes={}",
        signed21_compact_compiled.len()
    );
    println!(
        "compact_signed21_decoder_static_non_push_opcodes={}",
        static_non_push_opcodes(&signed21_compact_compiled)
    );
    println!("compact_signed21_strict_combined_stack_peak={signed21_compact_peak}");
    println!("compact_signed20_input_items=1");
    println!("compact_signed20_output_items=2");
    println!("compact_signed20_metadata_chunk_bits=12");
    println!(
        "compact_signed20_decoder_raw_bytes={}",
        raw_fragment_len(signed20_compact_decoder)
    );
    println!(
        "compact_signed20_decoder_policy_bytes={}",
        signed20_compact_compiled.len()
    );
    println!(
        "compact_signed20_decoder_static_non_push_opcodes={}",
        static_non_push_opcodes(&signed20_compact_compiled)
    );
    println!("compact_signed20_strict_combined_stack_peak={signed20_compact_peak}");
    println!("compact_pair_output_items=3");
    println!("compact_pair_logical_quotient_hint_items=2");
    println!("compact_pair_incremental_hint_items=0");
    println!("compact_pair_retained_metadata_items=1");
    println!("compact_first_pair_two_padding_input_items=4");
    println!("compact_first_pair_two_padding_chunk_bits=21");
    println!(
        "compact_first_pair_two_padding_decoder_policy_bytes={}",
        first_pair_two_padding.len()
    );
    println!(
        "compact_first_pair_two_padding_strict_combined_stack_peak={first_pair_two_padding_peak}"
    );
    println!("compact_regular_pair_two_padding_input_items=4");
    println!("compact_regular_pair_two_padding_chunk_bits=20");
    println!(
        "compact_regular_pair_two_padding_decoder_policy_bytes={}",
        regular_pair_two_padding.len()
    );
    println!(
        "compact_regular_pair_two_padding_strict_combined_stack_peak={regular_pair_two_padding_peak}"
    );
    println!("compact_regular_pair_no_padding_input_items=2");
    println!("compact_regular_pair_no_padding_chunk_bits=18");
    println!(
        "compact_regular_pair_no_padding_decoder_policy_bytes={}",
        regular_pair_no_padding.len()
    );
    println!(
        "compact_regular_pair_no_padding_strict_combined_stack_peak={regular_pair_no_padding_peak}"
    );
    println!("compact_pair_padding_bits_are_previously_certified_data=true");
    println!("padding_word_input_items=1");
    println!("padding_word_output_items=2");
    println!("padding_word_hint_items=0");
    println!("padding_word_incremental_data_items=0");
    println!("padding_word_metadata_bits=1");
    println!(
        "padding_word_decoder_raw_bytes={}",
        raw_fragment_len(padding_decoder)
    );
    println!(
        "padding_word_decoder_policy_bytes={}",
        padding_compiled.len()
    );
    println!(
        "padding_word_decoder_static_non_push_opcodes={}",
        static_non_push_opcodes(&padding_compiled)
    );
    println!("padding_word_strict_combined_stack_peak={padding_peak}");
    println!("canonical_padded_field_input_items=8");
    println!("canonical_padded_field_output_items=52");
    println!("canonical_padded_field_hint_items=0");
    println!(
        "canonical_padded_field_decoder_policy_bytes={}",
        field_decoder.len()
    );
    println!(
        "canonical_padded_field_strict_combined_stack_peak={}",
        field_peak_zero.max(field_peak_one)
    );
    println!("canonical_padded_field_fixture_zero_bit_witness_bytes={field_witness_zero}");
    println!("canonical_padded_field_fixture_one_bit_witness_bytes={field_witness_one}");
    println!("first_28_transition_q_hint_items={first_prefix_q_hints}");
    println!("first_28_transition_q_metadata_bits={first_prefix_q_capacity}");
    println!(
        "first_28_carrier_hint_vector_witness_bytes_upper_bound={first_prefix_carrier_witness_upper_bound}"
    );
    println!(
        "first_28_same_q_payload_overhead_bytes_upper_bound={first_prefix_same_q_payload_overhead_upper_bound}"
    );
    println!("first_28_padding_fields_modeled={transcript_probe_padding_fields}");
    println!(
        "first_28_q_plus_8_padding_capacity_bits={}",
        first_prefix_q_capacity + transcript_probe_padding_fields
    );
    println!("minimum_padding_bits_needed_by_capacity={padding_bits_needed_for_transcript}");
    println!("scheduled_padding_fields={transcript_probe_padding_fields}");
    println!("actual_stream_all_eight_padding_bits_in_transcript=true");
    println!("actual_stream_forced_zero_spare_source=final_response_q_metadata_bit");
    println!("complete_logical_q_hint_items={complete_q_hints}");
    println!("all_q_hints_coexist_at_script_entry=true");
    println!("complete_q_metadata_capacity_bits={complete_q_capacity}");
    println!(
        "complete_carrier_hint_vector_witness_bytes_upper_bound={complete_carrier_witness_upper_bound}"
    );
    println!(
        "complete_same_q_payload_overhead_bytes_upper_bound={complete_same_q_payload_overhead_upper_bound}"
    );
    println!("complete_trace_field_data_items={trace_data_items}");
    println!("complete_scalar_data_items_at_entry=0");
    println!("complete_entry_items={complete_entry_items}");
    println!("complete_q_headroom_over_765_bits={complete_q_headroom_over_payload}");
    println!(
        "complete_q_plus_8_padding_capacity_bits={}",
        complete_q_capacity + transcript_probe_padding_fields
    );
    println!("scalar_carrier_q_items={SCALAR_CARRIER_Q_ITEMS}");
    println!("scalar_carrier_capacity_bits={scalar_carrier_capacity}");
    println!(
        "scalar_carrier_spare_bits={}",
        scalar_carrier_capacity - 253
    );
    println!("scalar_extraction_output_word_items={EXTRACTED_SCALAR_WORD_ITEMS}");
    println!("modeled_live_items_after_scalar_extraction={live_items_after_scalar_extraction}");
    println!(
        "modeled_scalar_streaming_transient_upper_bound={scalar_streaming_transient_upper_bound}"
    );
    println!("scalar_streaming_transient_bound_includes_deep_roll_constant=true");
    println!("scalar_extraction_and_q_restoration_routing_implemented=false");
    println!("incremental_entry_items_for_carried_bits=0");
    println!("whole_scalar_multiplication_peak_unmeasured=true");
    println!("missing_negative_2pow31_code_rejected=true");
    println!("actual_proved_quotient_intervals_avoid_missing_code=true");
    println!("metadata_order_and_consumer_binding_required=true");
    println!("quotient_relation_binding_required=true");
    println!("packed_field_canonicality_checked_after_padding_clear=true");
    println!("includes=fragment-only: carrier decoding, raw canonicality, strict boundary fixtures, and one canonical packed-field restoration; scalar kernels, transcript consumer, and terminal predicate excluded");
}
