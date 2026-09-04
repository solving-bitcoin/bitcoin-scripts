//! Fast host-only checks for the external public-key boundary used by the H16
//! key-specialized table generator.
//!
//! This does not build table scripts and does not execute Bitcoin Script.
//! Run with:
//! `cargo run --locked --example ed25519_h16_public_key_boundary`.

#[allow(dead_code)]
#[path = "ed25519_fixed_table_actual_model.rs"]
mod table_model;

use table_model::{
    h16_benchmark_key_matches_disclosed_scalar,
    montgomery_direct_h16_independent_byte_table_fragments_for_public_key,
    validate_ed25519_public_key, Ed25519PublicKeyError, H16_BENCHMARK_PUBLIC_KEY_COMPRESSED,
};

fn expect_rejected(encoded: [u8; 32], expected: Ed25519PublicKeyError) {
    // Exercise the real production table API. Invalid keys return before any
    // table points or Script decision trees are generated.
    match montgomery_direct_h16_independent_byte_table_fragments_for_public_key(encoded) {
        Ok(_) => panic!("table generator unexpectedly accepted key rejected as {expected}"),
        Err(actual) => assert_eq!(actual, expected),
    }
}

fn main() {
    // RFC 8032 section 5.1's standard base-point encoding.
    let mut basepoint = [0x66u8; 32];
    basepoint[0] = 0x58;
    let validated_basepoint =
        validate_ed25519_public_key(basepoint).expect("the Ed25519 base point is valid");
    assert_eq!(validated_basepoint.compressed(), basepoint);

    // The disclosed benchmark key still passes through exactly the same
    // external-key boundary as a production key.
    let validated_fixture = validate_ed25519_public_key(H16_BENCHMARK_PUBLIC_KEY_COMPRESSED)
        .expect("the benchmark public point is valid");
    assert_eq!(
        validated_fixture.compressed(),
        H16_BENCHMARK_PUBLIC_KEY_COMPRESSED
    );
    assert!(h16_benchmark_key_matches_disclosed_scalar());

    // y=2 is canonical but its recovered x^2 is nonsquare.
    let mut not_on_curve = [0u8; 32];
    not_on_curve[0] = 2;
    expect_rejected(not_on_curve, Ed25519PublicKeyError::NotOnCurve);

    // y=p is an alternate/noncanonical field encoding.
    let mut noncanonical_y = [0xffu8; 32];
    noncanonical_y[0] = 0xed;
    noncanonical_y[31] = 0x7f;
    expect_rejected(noncanonical_y, Ed25519PublicKeyError::NonCanonicalY);

    // x=0 has only sign zero. Setting its sign bit is malformed even though
    // clearing it would produce the identity encoding.
    let mut negative_zero_x = [0u8; 32];
    negative_zero_x[0] = 1;
    negative_zero_x[31] = 0x80;
    expect_rejected(negative_zero_x, Ed25519PublicKeyError::InvalidSignOfZero);

    let mut identity = [0u8; 32];
    identity[0] = 1;
    expect_rejected(identity, Ed25519PublicKeyError::Identity);

    // (0,-1), the non-identity order-two point.
    let mut order_two = [0xffu8; 32];
    order_two[0] = 0xec;
    order_two[31] = 0x7f;
    expect_rejected(order_two, Ed25519PublicKeyError::SmallOrder);

    // B+T=(-x_B,-y_B) has a large prime-order component, so it is not itself
    // small order, but [l](B+T)=T. This specifically exercises the final
    // prime-subgroup check rather than only the cofactor check.
    let mixed_torsion = [0x95u8; 32];
    expect_rejected(mixed_torsion, Ed25519PublicKeyError::NotPrimeSubgroup);

    println!("model=ed25519_h16_external_public_key_boundary");
    println!("evidence=locally-reproduced");
    println!("execution_class=unclassified");
    println!("boundary=host-only_compile-time_public_key_validation");
    println!("valid_keys=RFC8032_basepoint,disclosed_benchmark_public_point");
    println!(
        "rejected=not_on_curve,noncanonical_y,negative_zero_x,identity,small_order,mixed_torsion"
    );
    println!("prime_subgroup_check=[l]A=identity");
    println!("table_scripts_built=false");
    println!("bitcoin_script_executed=false");
    println!("secret_scalar_input_items=0");
    println!("production_table_schedule=independent_signed_bytes_bias127");
    println!("benchmark_default_key_unchanged=true");
    println!("witness_hint_items=0");
}
