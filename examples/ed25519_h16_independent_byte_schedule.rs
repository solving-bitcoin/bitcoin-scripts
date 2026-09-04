//! Focused host/Script probe for the H16 independent bias-127 challenge
//! schedule. It executes only the 389-byte recoder and host group algebra;
//! the large generated tables are serialized for exact byte accounting but
//! are never executed.

#[path = "ed25519_fixed_table_actual_model.rs"]
mod fixed_tables;
#[path = "ed25519_h16_midpoint_glue.rs"]
mod midpoint;

use bitcoin_lab::support::{
    execution::execute_raw_script_with_inputs_strict,
    script::{script, Script, ScriptCompilation, MAX_OPTIMIZER_INPUT_BYTES},
};

const PRESERVED_ITEMS: usize = 337;
const DIGEST_BYTES: usize = 16;
const EXPECTED_OLD_TABLE_BYTES: usize = 838_456;
const EXPECTED_NEW_TABLE_BYTES: usize = 826_072;
const EXPECTED_TABLE_SAVING_BYTES: usize = 12_384;
const EXPECTED_OLD_RECODER_BYTES: usize = 580;
const EXPECTED_NEW_RECODER_BYTES: usize = 389;

fn scriptnum_item(value: i64) -> Vec<u8> {
    let mut bytes = [0u8; 8];
    let length = bitcoin::script::write_scriptint(&mut bytes, value);
    bytes[..length].to_vec()
}

fn raw_fragment_len(fragment: &Script, copies: usize) -> usize {
    let repeated = script! {
        for _ in 0..copies { { fragment.clone() } }
    }
    .compile_with_policy();
    assert!(repeated.len() > MAX_OPTIMIZER_INPUT_BYTES);
    assert_eq!(repeated.len() % copies, 0);
    repeated.len() / copies
}

fn raw_sequence_len(fragments: &[Script]) -> usize {
    let combined = script! {
        for fragment in fragments { { fragment.clone() } }
    }
    .compile_with_policy();
    assert!(combined.len() > MAX_OPTIMIZER_INPUT_BYTES);
    combined.len()
}

fn digest_u4(bytes: &[u8; DIGEST_BYTES]) -> Vec<Vec<u8>> {
    bytes
        .iter()
        .flat_map(|byte| [byte >> 4, byte & 0x0f])
        .map(|nibble| scriptnum_item(i64::from(nibble)))
        .collect()
}

fn controls(bytes: &[u8; DIGEST_BYTES]) -> Vec<(bool, u32)> {
    bytes
        .iter()
        .copied()
        .map(|byte| {
            let (negative, magnitude) = fixed_tables::h16_independent_challenge_control(byte);
            (negative, magnitude as u32)
        })
        .collect()
}

fn recoder_checker(expected: &[(bool, u32)]) -> bitcoin::ScriptBuf {
    assert_eq!(expected.len(), DIGEST_BYTES);
    let recoder = midpoint::recode_h16_blake3_low128_independent_byte127().compile_with_policy();
    script! {
        { Script::new("policy-precompiled independent-byte recoder").push_script(recoder) }
        for (negative, magnitude) in expected.iter().rev() {
            { *magnitude } OP_NUMEQUALVERIFY
            { u32::from(*negative) } OP_NUMEQUALVERIFY
        }
        for _ in 0..PRESERVED_ITEMS { 11 OP_NUMEQUALVERIFY }
        OP_1
    }
    .compile_with_policy()
}

fn strict_recoder_peak(bytes: &[u8; DIGEST_BYTES]) -> usize {
    let expected = controls(bytes);
    let script = recoder_checker(&expected);
    let mut witness = vec![scriptnum_item(11); PRESERVED_ITEMS];
    witness.extend(digest_u4(bytes));
    let execution = execute_raw_script_with_inputs_strict(script.to_bytes(), witness);
    assert!(
        execution.error.is_none(),
        "independent recoder: {execution}"
    );
    assert_eq!(execution.final_stack.len(), 1);
    execution.stats.max_nb_stack_items
}

fn main() {
    // This audit includes the response boundaries s=0,1,l-1, uniform
    // challenge boundaries 00/7f/80/ff, exact K_127 reconstruction, and the
    // torsion-translated final endpoint. It builds no Script tables.
    fixed_tables::verify_h16_independent_byte_host_algebra();
    assert_eq!(
        fixed_tables::h16_independent_challenge_bias_scalar().to_bytes_le(),
        [0x7fu8; DIGEST_BYTES]
    );
    assert_eq!(
        fixed_tables::h16_independent_challenge_control(0x00),
        (true, 127)
    );
    assert_eq!(
        fixed_tables::h16_independent_challenge_control(0x7f),
        (false, 0)
    );
    assert_eq!(
        fixed_tables::h16_independent_challenge_control(0x80),
        (false, 1)
    );
    assert_eq!(
        fixed_tables::h16_independent_challenge_control(0xff),
        (false, 128)
    );

    let boundary_inputs = [
        [0x00u8; DIGEST_BYTES],
        [0x7f; DIGEST_BYTES],
        [0x80; DIGEST_BYTES],
        [0xff; DIGEST_BYTES],
        std::array::from_fn(|index| [0x00, 0x7f, 0x80, 0xff][index % 4]),
    ];
    let strict_peak = boundary_inputs
        .iter()
        .map(strict_recoder_peak)
        .max()
        .expect("five recoder probes");
    assert_eq!(strict_peak, 371);

    let old_recoder = midpoint::recode_h16_blake3_low128();
    let new_recoder = midpoint::recode_h16_blake3_low128_independent_byte127();
    let old_recoder_raw = raw_fragment_len(&old_recoder, 128);
    let new_recoder_raw = raw_fragment_len(&new_recoder, 128);
    let new_recoder_policy = new_recoder.compile_with_policy().len();
    assert_eq!(old_recoder_raw, EXPECTED_OLD_RECODER_BYTES);
    assert_eq!(new_recoder_raw, EXPECTED_NEW_RECODER_BYTES);
    assert_eq!(new_recoder_policy, EXPECTED_NEW_RECODER_BYTES);

    // Generation/serialization only: no table Script or slope kernel runs.
    let old = fixed_tables::montgomery_direct_h16_table_fragments();
    let new = fixed_tables::montgomery_direct_h16_independent_byte_table_fragments();
    assert_eq!(old.public_key_compressed, new.public_key_compressed);
    assert_eq!(old.response_low_to_high.len(), 29);
    assert_eq!(old.challenge_low_to_high.len(), DIGEST_BYTES);
    assert_eq!(new.response_low_to_high.len(), 29);
    assert_eq!(new.challenge_low_to_high.len(), DIGEST_BYTES);

    let old_response_lower = raw_sequence_len(&old.response_low_to_high[..28]);
    let old_response_top = raw_fragment_len(&old.response_low_to_high[28], 4);
    let old_challenge_lower = raw_sequence_len(&old.challenge_low_to_high[..15]);
    let old_challenge_top = raw_fragment_len(&old.challenge_low_to_high[15], 4);
    let new_response_lower = raw_sequence_len(&new.response_low_to_high[..28]);
    let new_response_top = raw_fragment_len(&new.response_low_to_high[28], 4);
    let new_challenge_lower = raw_sequence_len(&new.challenge_low_to_high[..15]);
    let new_challenge_top = raw_fragment_len(&new.challenge_low_to_high[15], 4);
    let old_table_bytes =
        old_response_lower + old_response_top + old_challenge_lower + old_challenge_top;
    let new_table_bytes =
        new_response_lower + new_response_top + new_challenge_lower + new_challenge_top;
    let table_saving = old_table_bytes - new_table_bytes;

    assert_eq!(old_table_bytes, EXPECTED_OLD_TABLE_BYTES);
    assert_eq!(new_table_bytes, EXPECTED_NEW_TABLE_BYTES);
    assert_eq!(table_saving, EXPECTED_TABLE_SAVING_BYTES);
    assert_eq!(new_response_lower, old_response_lower);
    assert_eq!(new_challenge_lower, old_challenge_lower);
    assert_eq!(new_response_top - old_response_top, 57);
    assert_eq!(old_challenge_top - new_challenge_top, 12_441);

    println!("model=ed25519_h16_independent_bias127_schedule");
    println!("evidence=locally-reproduced");
    println!("execution_class=unclassified");
    println!("large_table_or_full_scalar_script_executed=false");
    println!("challenge_identity=h=sum(e_i*2^(8i))+K_127");
    println!("challenge_bias_scalar_le_hex=7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f");
    println!("challenge_digit_interval=-127..128");
    println!("challenge_selector_magnitude_interval=0..128");
    println!("challenge_groups=16");
    println!("challenge_top_candidate_leaves_old=257");
    println!("challenge_top_candidate_leaves_new=129");
    println!("response_initializer_shift=-K_127_times_A");
    println!("response_lower_table_bytes={old_response_lower}");
    println!("response_top_table_bytes_old={old_response_top}");
    println!("response_top_table_bytes_new={new_response_top}");
    println!("challenge_lower_table_bytes={old_challenge_lower}");
    println!("challenge_top_table_bytes_old={old_challenge_top}");
    println!("challenge_top_table_bytes_new={new_challenge_top}");
    println!("table_bytes_old={old_table_bytes}");
    println!("table_bytes_new={new_table_bytes}");
    println!("table_saving_bytes={table_saving}");
    println!("recoder_bytes_old={old_recoder_raw}");
    println!("recoder_bytes_new={new_recoder_raw}");
    println!(
        "table_plus_recoder_saving_bytes={}",
        table_saving + old_recoder_raw - new_recoder_raw
    );
    println!("recoder_hint_items=0");
    println!("table_selector_hint_items=0");
    println!("slope_relation_quotient_hint_items_unchanged=88");
    println!("complete_scalar_entry_items_unchanged=792");
    println!("all_entry_items_coexist_at_script_entry=true");
    println!("strict_recoder_preserved_items={PRESERVED_ITEMS}");
    println!("strict_recoder_input_items={}", PRESERVED_ITEMS + 32);
    println!("strict_recoder_combined_stack_peak={strict_peak}");
}
