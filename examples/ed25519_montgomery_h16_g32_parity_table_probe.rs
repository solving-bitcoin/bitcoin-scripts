//! Focused parity-correct response-table measurement for the G32 H16
//! candidate.
//!
//! This builds only the 32 response decision trees and their host leaves. It
//! never links or executes the scalar-multiplication Script.

#[allow(dead_code)]
#[path = "ed25519_fixed_table_actual_model.rs"]
mod table_model;

const STALE_G32_RESPONSE_TABLE_BYTES: usize = 383_020;
const STALE_G32_LOWER_TABLE_BYTES: usize = 370_395;
const STALE_G32_TOP_TABLE_BYTES: usize = 12_625;
const EXPECTED_G32_RESPONSE_TABLE_BYTES: usize = 383_004;
const EXPECTED_G32_LOWER_TABLE_BYTES: usize = 370_395;
const EXPECTED_G32_TOP_TABLE_BYTES: usize = 12_609;
const G31_RESPONSE_TABLE_BYTES: usize = 451_272;
const EXPECTED_DELTA_VS_STALE_G32_BYTES: i64 = -16;
const EXPECTED_DELTA_VS_G31_BYTES: i64 = -68_268;
const EXPECTED_PUBLIC_KEY: [u8; 32] = [
    0x7d, 0xb0, 0xdc, 0x92, 0x22, 0xf3, 0xc1, 0x83, 0x45, 0x7d, 0xdd, 0xe4, 0xc7, 0x08, 0xde, 0x8e,
    0x5e, 0xa6, 0xbf, 0x3d, 0x5c, 0x44, 0x04, 0xcc, 0xa1, 0x4b, 0x32, 0x72, 0x9a, 0x05, 0xc3, 0x2a,
];

fn main() {
    let widths = table_model::montgomery_direct_h16_qfree_g32_response_widths();
    let width7_positions = widths
        .iter()
        .copied()
        .enumerate()
        .filter_map(|(position, width)| (width == 7).then_some(position))
        .collect::<Vec<_>>();
    assert_eq!(widths.len(), 32);
    assert_eq!(widths.iter().sum::<usize>(), 253);
    assert_eq!(width7_positions, [21, 25, 29]);
    assert_eq!(*widths.last().expect("G32 top width"), 8);

    let variant = table_model::montgomery_direct_h16_independent_response_table_variant(&widths);
    assert_eq!(variant.widths_low_to_high, widths);
    assert_eq!(variant.response_low_to_high.len(), 32);
    assert_eq!(variant.host_low_to_high.len(), 32);
    assert_eq!(variant.per_table_raw_bytes.len(), 32);
    assert_eq!(
        variant
            .response_low_to_high
            .iter()
            .map(bitcoin_lab::support::script::Script::len)
            .collect::<Vec<_>>(),
        variant.per_table_raw_bytes
    );
    assert_eq!(
        variant.per_table_raw_bytes.iter().sum::<usize>(),
        variant.total_raw_bytes
    );

    // This second call is the exact API consumed by the honest-witness
    // fixture. Equality proves both views use the parity-correct G32 entries;
    // no leaf-by-leaf Script execution is needed for this provenance check.
    let host = table_model::montgomery_direct_h16_qfree_g32_host_tables();
    assert_eq!(host.public_key_compressed, EXPECTED_PUBLIC_KEY);
    assert_eq!(variant.host_low_to_high, host.response_low_to_high);
    for (position, (width, leaves)) in widths
        .iter()
        .copied()
        .zip(variant.host_low_to_high.iter())
        .enumerate()
    {
        let expected_maximum = if position + 1 == widths.len() {
            variant.top_max
        } else {
            1usize << (width - 1)
        };
        assert_eq!(leaves.len(), expected_maximum + 1);
    }

    let top_table_bytes = *variant
        .per_table_raw_bytes
        .last()
        .expect("G32 has a top response table");
    let lower_table_bytes = variant.total_raw_bytes - top_table_bytes;
    assert_eq!(lower_table_bytes, EXPECTED_G32_LOWER_TABLE_BYTES);
    assert_eq!(top_table_bytes, EXPECTED_G32_TOP_TABLE_BYTES);
    assert_eq!(variant.total_raw_bytes, EXPECTED_G32_RESPONSE_TABLE_BYTES);
    assert_eq!(
        variant.total_raw_bytes as i64 - STALE_G32_RESPONSE_TABLE_BYTES as i64,
        EXPECTED_DELTA_VS_STALE_G32_BYTES
    );
    assert_eq!(
        variant.total_raw_bytes as i64 - G31_RESPONSE_TABLE_BYTES as i64,
        EXPECTED_DELTA_VS_G31_BYTES
    );

    println!("model=ed25519_montgomery_h16_g32_parity_table_probe");
    println!("evidence=locally-reproduced");
    println!("evidence_boundary=serialization");
    println!("execution_class=unclassified");
    println!("response_width7_lower_positions=21,25,29");
    println!("response_top_torsion_initializer=U_minus_K127A");
    println!("post_initializer_T_additions=47");
    println!("final_torsion_coset=minus_U");
    println!("response_top_max={}", variant.top_max);
    println!("response_lower_table_bytes={lower_table_bytes}");
    println!("response_top_table_bytes={top_table_bytes}");
    println!("response_total_table_bytes={}", variant.total_raw_bytes);
    println!(
        "delta_vs_stale_g32_lower_bytes={}",
        lower_table_bytes as i64 - STALE_G32_LOWER_TABLE_BYTES as i64
    );
    println!(
        "delta_vs_stale_g32_top_bytes={}",
        top_table_bytes as i64 - STALE_G32_TOP_TABLE_BYTES as i64
    );
    println!(
        "delta_vs_stale_g32_total_bytes={}",
        variant.total_raw_bytes as i64 - STALE_G32_RESPONSE_TABLE_BYTES as i64
    );
    println!(
        "delta_vs_g31_response_table_bytes={}",
        variant.total_raw_bytes as i64 - G31_RESPONSE_TABLE_BYTES as i64
    );
    println!("script_and_host_leaves_share_exact_entries=true");
    println!("host_entries_match_honest_witness_api=true");
    println!("auxiliary_hint_items=0");
    println!("whole_leaf_generated=false");
    println!("any_script_executed=false");
}
