//! README metric snapshots.
//!
//! Run with `UPDATE_PRIMITIVE_METRICS=1 cargo test --test primitive_metrics`
//! after intentionally changing a measured script. A normal test run fails if
//! a README still contains the old value.

use std::{env, fs, path::Path};

use bitcoin::consensus::encode::serialize;
use bitcoin::{script::Instruction, Witness};
use bitcoin_lab::arithmetic::rns::prime::carry::{bound, composable};
use bitcoin_lab::{
    arithmetic::{
        bigint::U254,
        fields::{f12289, f257},
        rns, scriptint, u31, u32, u4,
    },
    ciphers::{aes, prince},
    commitments::{
        four_way_hash_path_integer_commitment, four_way_hash_path_integer_witness,
        hash_path_integer_commitment, hash_path_integer_witness, preimage_length_commitment,
        verify_four_way_hash_path_to_integer, verify_hash_path_to_integer, verify_preimage_length,
    },
    curves::bn254::{
        fields::{fp254::Fp254Impl, fq::Fq, fq2::Fq2, fr::Fr},
        groups::{g1::G1Affine, g2::G2Affine},
    },
    hashes::{blake3, ripemd160, sha1, sha256, shake256},
    signatures::{
        hors, lamport,
        winternitz::{Wots, Wots32},
    },
    support::execution::execute_script_with_inputs,
};
use bitcoin_script::script;
use num_bigint::{BigInt, BigUint};
use num_traits::One;

struct Metric {
    readme: &'static str,
    key: &'static str,
    value: usize,
}

fn script_len(script: bitcoin_script::Script) -> usize {
    script.compile().len()
}

fn static_non_push_opcodes(script: bitcoin_script::Script) -> usize {
    script
        .compile()
        .instructions()
        .map(|instruction| instruction.expect("generated metric script must parse"))
        .filter(
            |instruction| matches!(instruction, Instruction::Op(opcode) if opcode.to_u8() > 0x60),
        )
        .count()
}

fn witness_size(items: &[Vec<u8>]) -> usize {
    serialize(&Witness::from_slice(items)).len()
}

fn scriptnum(value: i64) -> Vec<u8> {
    let mut bytes = [0u8; 8];
    let len = bitcoin::script::write_scriptint(&mut bytes, value);
    bytes[..len].to_vec()
}

fn max_stack_items(script: bitcoin_script::Script, witness: Vec<Vec<u8>>) -> usize {
    let result = execute_script_with_inputs(script, witness);
    assert!(result.success, "metric execution failed: {result}");
    result.stats.max_nb_stack_items
}

fn metrics() -> Vec<Metric> {
    let rns_add = script! {
        { rns::rns_push_add_tables() }
        { rns::rns_add() }
        { rns::rns_drop_add_tables() }
        { rns::rns_fromaltstack() }
    };
    let rns_sub = script! {
        { rns::rns_push_sub_tables() }
        { rns::rns_sub() }
        { rns::rns_drop_sub_tables() }
        { rns::rns_fromaltstack() }
    };
    let rns_mul = script! {
        { rns::rns_push_mul_tables() }
        { rns::rns_mul() }
        { rns::rns_drop_mul_tables() }
        { rns::rns_fromaltstack() }
    };
    let prime_rns_add = script! {
        { rns::prime::add() }
        { rns::prime::from_altstack() }
    };
    let prime_rns_sub = script! {
        { rns::prime::sub() }
        { rns::prime::from_altstack() }
    };
    let prime_rns_centered_add = script! {
        { rns::prime::add_centered() }
        { rns::prime::from_altstack() }
    };
    let prime_rns_centered_sub = script! {
        { rns::prime::sub_centered() }
        { rns::prime::from_altstack() }
    };
    let prime_rns_mul = script! {
        { rns::prime::mul(0) }
        { rns::prime::from_altstack() }
    };
    let prime_rns_mul_cost = rns::prime::mul_cost_breakdown();
    let prime_rns_verify = script! {
        { rns::prime::verify_canonical() }
    };
    let prime_rns_hinted_target = BigUint::parse_bytes(
        b"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
        16,
    )
    .unwrap();
    let prime_rns_hinted_lhs = &prime_rns_hinted_target - BigUint::one();
    let prime_rns_hinted_rhs = prime_rns_hinted_lhs.clone();
    let prime_rns_hinted_product = &prime_rns_hinted_lhs * &prime_rns_hinted_rhs;
    let prime_rns_hinted_quotient = &prime_rns_hinted_product / &prime_rns_hinted_target;
    let prime_rns_hinted_remainder = &prime_rns_hinted_product % &prime_rns_hinted_target;
    let prime_rns_hinted_complement =
        &prime_rns_hinted_target - BigUint::one() - &prime_rns_hinted_remainder;
    let prime_rns_hinted_mul = rns::prime::mul_mod_hinted(&prime_rns_hinted_target, 0);
    let prime_rns_hinted_mul_cost =
        rns::prime::mul_mod_hinted_cost_breakdown(&prime_rns_hinted_target);
    let prime_rns_hinted_mul_opcodes = static_non_push_opcodes(prime_rns_hinted_mul.clone());
    let mut prime_rns_hinted_hint_items = Vec::new();
    for value in [
        &prime_rns_hinted_quotient,
        &prime_rns_hinted_remainder,
        &prime_rns_hinted_complement,
    ] {
        for residue in rns::prime::encode(value).iter().rev() {
            prime_rns_hinted_hint_items.push(scriptnum(i64::from(*residue)));
        }
    }
    let mut prime_rns_hinted_input_items = Vec::new();
    for value in [
        &prime_rns_hinted_lhs,
        &prime_rns_hinted_rhs,
        &prime_rns_hinted_quotient,
        &prime_rns_hinted_remainder,
        &prime_rns_hinted_complement,
    ] {
        for residue in rns::prime::encode(value).iter().rev() {
            prime_rns_hinted_input_items.push(scriptnum(i64::from(*residue)));
        }
    }
    let prime_rns_carry_hinted_carries = rns::prime::carry::relation_carries(
        &prime_rns_hinted_lhs,
        &prime_rns_hinted_rhs,
        &prime_rns_hinted_quotient,
        &prime_rns_hinted_remainder,
        &prime_rns_hinted_target,
    );
    let prime_rns_carry_hinted_mul = rns::prime::carry::mul_mod_hinted(&prime_rns_hinted_target, 0);
    let prime_rns_carry_hinted_mul_cost =
        rns::prime::carry::mul_mod_hinted_cost_breakdown(&prime_rns_hinted_target);
    let prime_rns_carry_hinted_mul_opcodes =
        static_non_push_opcodes(prime_rns_carry_hinted_mul.clone());
    let carry_lhs = rns::prime::carry::encode(&prime_rns_hinted_lhs);
    let carry_rhs = rns::prime::carry::encode(&prime_rns_hinted_rhs);
    let carry_quotient = rns::prime::carry::encode(&prime_rns_hinted_quotient);
    let carry_remainder = rns::prime::carry::encode(&prime_rns_hinted_remainder);
    let carry_complement = rns::prime::carry::encode(&prime_rns_hinted_complement);
    let mut prime_rns_carry_hinted_hint_items = Vec::new();
    let mut prime_rns_carry_hinted_input_items = Vec::new();
    for index in (0..rns::prime::carry::MODULI.len()).rev() {
        prime_rns_carry_hinted_input_items.push(scriptnum(i64::from(carry_lhs[index])));
        prime_rns_carry_hinted_input_items.push(scriptnum(i64::from(carry_rhs[index])));
        for residue in [carry_quotient[index], carry_remainder[index]] {
            let item = scriptnum(i64::from(residue));
            prime_rns_carry_hinted_hint_items.push(item.clone());
            prime_rns_carry_hinted_input_items.push(item);
        }
        if rns::prime::carry::COMPLEMENT_INDICES
            .binary_search(&index)
            .is_ok()
        {
            let item = scriptnum(i64::from(carry_complement[index]));
            prime_rns_carry_hinted_hint_items.push(item.clone());
            prime_rns_carry_hinted_input_items.push(item);
        }
        let item = scriptnum(i64::from(prime_rns_carry_hinted_carries[index]));
        prime_rns_carry_hinted_hint_items.push(item.clone());
        prime_rns_carry_hinted_input_items.push(item);
    }
    let prime_rns_bound_carry_mul = bound::mul_mod_hinted(&prime_rns_hinted_target, 0);
    let prime_rns_bound_carry_cost = bound::cost_breakdown(&prime_rns_hinted_target);
    let prime_rns_bound_carry_opcodes = static_non_push_opcodes(prime_rns_bound_carry_mul.clone());
    let bound_lhs_limbs = bound::centered_limbs(&prime_rns_hinted_lhs);
    let bound_rhs_limbs = bound::centered_limbs(&prime_rns_hinted_rhs);
    let bound_quotient_limbs = bound::centered_limbs(&prime_rns_hinted_quotient);
    let bound_remainder_limbs = bound::centered_limbs(&prime_rns_hinted_remainder);
    let bound_lhs_carries = bound::binding_carries(&prime_rns_hinted_lhs);
    let bound_rhs_carries = bound::binding_carries(&prime_rns_hinted_rhs);
    let bound_quotient_carries = bound::binding_carries(&prime_rns_hinted_quotient);
    let bound_remainder_carries = bound::binding_carries(&prime_rns_hinted_remainder);
    let bound_relation_carries = bound::relation_carries(
        &prime_rns_hinted_lhs,
        &prime_rns_hinted_rhs,
        &prime_rns_hinted_quotient,
        &prime_rns_hinted_remainder,
        &prime_rns_hinted_target,
    );
    let mut prime_rns_bound_carry_input_items = Vec::new();
    for limbs in [
        &bound_remainder_limbs,
        &bound_quotient_limbs,
        &bound_rhs_limbs,
        &bound_lhs_limbs,
    ] {
        for limb in limbs.iter().rev() {
            prime_rns_bound_carry_input_items.push(scriptnum(i64::from(*limb)));
        }
    }
    for index in (0..bound::MODULI.len()).rev() {
        for carry in [
            bound_lhs_carries[index],
            bound_rhs_carries[index],
            bound_quotient_carries[index],
            bound_remainder_carries[index],
            bound_relation_carries[index],
        ] {
            prime_rns_bound_carry_input_items.push(scriptnum(i64::from(carry)));
        }
    }
    let prime_rns_bind_value = bound::bind_value(0);
    let prime_rns_bind_value_below = bound::bind_value_below(&prime_rns_hinted_target, 0);
    let prime_rns_bind_value_cost = bound::bind_value_cost_breakdown();
    let prime_rns_composable_mul = composable::mul_mod_hinted(0);
    let prime_rns_composable_cost = composable::cost_breakdown();
    let prime_rns_composable_opcodes = static_non_push_opcodes(prime_rns_composable_mul.clone());
    let composable_quotient_limbs = composable::centered_limbs(&prime_rns_hinted_quotient);
    let composable_remainder_limbs = composable::centered_limbs(&prime_rns_hinted_remainder);
    let composable_quotient_binding = composable::binding_carries(&prime_rns_hinted_quotient);
    let composable_remainder_binding = composable::binding_carries(&prime_rns_hinted_remainder);
    let composable_relation = composable::relation_carries(
        &prime_rns_hinted_lhs,
        &prime_rns_hinted_rhs,
        &prime_rns_hinted_quotient,
        &prime_rns_hinted_remainder,
    );
    let mut prime_rns_composable_hint_items = Vec::new();
    for limbs in [&composable_quotient_limbs, &composable_remainder_limbs] {
        for limb in limbs.iter().rev() {
            prime_rns_composable_hint_items.push(scriptnum(i64::from(*limb)));
        }
    }
    for index in (0..composable::MODULI.len()).rev() {
        for carry in [
            composable_quotient_binding[index],
            composable_remainder_binding[index],
            composable_relation[index],
        ] {
            prime_rns_composable_hint_items.push(scriptnum(i64::from(carry)));
        }
    }
    let mut prime_rns_composable_input_items = Vec::new();
    for value in [&prime_rns_hinted_lhs, &prime_rns_hinted_rhs] {
        for residue in composable::encode(value).iter().rev() {
            prime_rns_composable_input_items.push(scriptnum(i64::from(*residue)));
        }
    }
    prime_rns_composable_input_items.extend(prime_rns_composable_hint_items.iter().cloned());
    let prime_rns_composable_bind = composable::bind_value(0);
    let prime_rns_composable_bind_cost = composable::bind_value_cost_breakdown();
    let prime_rns_composable_bind_opcodes =
        static_non_push_opcodes(prime_rns_composable_bind.clone());
    let composable_bind_limbs = composable::centered_limbs(&prime_rns_hinted_lhs);
    let composable_bind_carries = composable::binding_carries(&prime_rns_hinted_lhs);
    let mut prime_rns_composable_bind_items = Vec::new();
    for limb in composable_bind_limbs.iter().rev() {
        prime_rns_composable_bind_items.push(scriptnum(i64::from(*limb)));
    }
    for carry in composable_bind_carries.iter().rev() {
        prime_rns_composable_bind_items.push(scriptnum(i64::from(*carry)));
    }
    let prime_rns_mul_opcodes = static_non_push_opcodes(prime_rns_mul.clone());
    let prime_rns_max = (BigUint::one() << 256usize) - BigUint::one();
    let prime_rns_rhs = &prime_rns_max - BigUint::one();
    let prime_rns_centered_lhs = BigInt::from(-1);
    let prime_rns_centered_rhs = BigInt::from(-2);
    let mut prime_rns_operand_items = Vec::new();
    for value in [&prime_rns_max, &prime_rns_rhs] {
        for residue in rns::prime::encode(value) {
            prime_rns_operand_items.push(scriptnum(i64::from(residue)));
        }
    }
    let prime_rns_max_value_items = rns::prime::encode(&prime_rns_max)
        .into_iter()
        .map(|residue| scriptnum(i64::from(residue)))
        .collect::<Vec<_>>();
    let prime_rns_worst_value_items = rns::prime::MODULI
        .into_iter()
        .map(|modulus| scriptnum(i64::from(modulus - 1)))
        .collect::<Vec<_>>();
    let prime_rns_worst_operand_items = prime_rns_worst_value_items
        .iter()
        .chain(&prime_rns_worst_value_items)
        .cloned()
        .collect::<Vec<_>>();
    let prime_rns_batch_products = rns::prime::batch::MAX_PRODUCTS;
    let prime_rns_batch_cost = rns::prime::batch::cost_breakdown(prime_rns_batch_products);
    let prime_rns_batch_mul = script! {
        { rns::prime::batch::mul(prime_rns_batch_products, 0) }
        for _ in 0..rns::prime::RESIDUE_COUNT * prime_rns_batch_products {
            OP_FROMALTSTACK
        }
    };
    let prime_rns_batch_lhs = rns::prime::encode(&prime_rns_max);
    let prime_rns_batch_rhs = rns::prime::encode(&prime_rns_rhs);
    let mut prime_rns_batch_input_items = Vec::new();
    for coordinate in (0..rns::prime::MODULI.len()).rev() {
        for _ in (0..prime_rns_batch_products).rev() {
            prime_rns_batch_input_items.push(scriptnum(i64::from(prime_rns_batch_lhs[coordinate])));
            prime_rns_batch_input_items.push(scriptnum(i64::from(prime_rns_batch_rhs[coordinate])));
        }
    }
    let f257_log_memory = script! {
        { f257::push_log_mul_tables() }
        { f257::drop_log_mul_tables() }
    };
    let f257_square_memory = script! {
        { f257::push_square_table() }
        { f257::drop_square_table() }
    };
    let f12289_radix128_memory = script! {
        { f12289::push_radix_mul_tables(10_000, 7) }
        { f12289::drop_radix_mul_tables(7) }
    };
    let f257_log_state_script = script! {
        { f257::push_log_mul_tables() }
        for _ in 0..510 {
            128
        }
        127 -128
        { f257::mul_from_log_tables(510) }
        -65 OP_EQUALVERIFY
        for _ in 0..510 {
            OP_DROP
        }
        { f257::drop_log_mul_tables() }
        OP_TRUE
    };
    let f257_log_constant_state_script = script! {
        { f257::push_log_mul_tables() }
        for _ in 0..511 {
            128
        }
        -128
        { f257::mul_by_constant_from_log_tables(173, 511) }
        -42 OP_EQUALVERIFY
        for _ in 0..511 {
            OP_DROP
        }
        { f257::drop_log_mul_tables() }
        OP_TRUE
    };
    let f257_square_state_script = script! {
        { f257::push_square_table() }
        for _ in 0..511 {
            128
        }
        -128
        { f257::square_from_table(511) }
        16384 OP_EQUALVERIFY
        for _ in 0..511 {
            OP_DROP
        }
        { f257::drop_square_table() }
        OP_TRUE
    };
    let f12289_radix128_state_script = script! {
        { f12289::push_radix_mul_tables(10_000, 7) }
        for _ in 0..511 {
            { 12_288u32 }
        }
        { 12_287u32 }
        { f12289::mul_by_constant_from_radix_tables(7, 511) }
        { (12_287u64 * 10_000 % 12_289) as u32 } OP_EQUALVERIFY
        for _ in 0..511 {
            OP_DROP
        }
        { f12289::drop_radix_mul_tables(7) }
        OP_TRUE
    };

    let lamport_preimages: [&[u8]; 4] = [b"secret0", b"secret1", b"secret2", b"secret3"];
    let (h0, h1, h2, h3) = lamport::lamport_2bit_public_keys(
        lamport_preimages[0],
        lamport_preimages[1],
        lamport_preimages[2],
        lamport_preimages[3],
    );
    let lamport_witness = vec![vec![1], lamport_preimages[1].to_vec()];

    let hors_preimages = (0u8..32).map(|i| vec![i; 32]).collect::<Vec<_>>();
    let hors_public_keys = hors::hors_public_keys(&hors_preimages);
    let hors_witness = hors::hors_unlocking_witness(&hors_preimages, &(0..8).collect::<Vec<_>>());

    let wots_secret = vec![0x42; 20];
    let wots_message = [0u8; 32];
    let wots_public_key = Wots32::generate_public_key(&wots_secret);
    let wots_witness = Wots32::sign_to_raw_witness(&wots_secret, &wots_message);

    let hash_path_preimage = vec![0x42; 32];
    let hash_path_value = 0x1234_5678;
    let hash_path_commitment =
        hash_path_integer_commitment(&hash_path_preimage, hash_path_value, 31);
    let hash_path_witness = hash_path_integer_witness(&hash_path_preimage, hash_path_value, 31);

    let four_way_hash_path_commitment =
        four_way_hash_path_integer_commitment(&hash_path_preimage, hash_path_value, 31);
    let four_way_hash_path_witness =
        four_way_hash_path_integer_witness(&hash_path_preimage, hash_path_value, 31);

    let length_preimage = vec![0x24; 32];
    let length_commitment = preimage_length_commitment(&length_preimage);

    let division_witness = vec![scriptnum(14), scriptnum(119)];
    let aes_zero_key = [0u8; 16];
    let aes_stack_script = script! {
        { aes::aes128_encrypt(aes_zero_key) }
        for _ in 0..16 {
            OP_2DROP
        }
        OP_1
    };

    vec![
        Metric {
            readme: "src/arithmetic/u4/README.md",
            key: "u4_add_tables",
            value: script_len(u4::add::u4_push_add_tables()),
        },
        Metric {
            readme: "src/arithmetic/u32/README.md",
            key: "u32_add_drop",
            value: script_len(u32::add::u32_add_drop(0, 1)),
        },
        Metric {
            readme: "src/arithmetic/u32/README.md",
            key: "u32_add_drop_stack",
            value: max_stack_items(
                script! {
                    { u32::stack::u32_push(0xffff_ffff) }
                    { u32::stack::u32_push(1) }
                    { u32::add::u32_add_drop(1, 0) }
                    { u32::stack::u32_drop() }
                    OP_1
                },
                vec![],
            ),
        },
        Metric {
            readme: "src/arithmetic/u32/README.md",
            key: "u32_sub_drop",
            value: script_len(u32::sub::u32_sub_drop(0, 1)),
        },
        Metric {
            readme: "src/arithmetic/u32/README.md",
            key: "u32_sub_drop_stack",
            value: max_stack_items(
                script! {
                    { u32::stack::u32_push(1) }
                    { u32::stack::u32_push(0) }
                    { u32::sub::u32_sub_drop(0, 1) }
                    { u32::stack::u32_drop() }
                    OP_1
                },
                vec![],
            ),
        },
        Metric {
            readme: "src/arithmetic/u32/README.md",
            key: "u32_lessthan",
            value: script_len(u32::cmp::u32_lessthan()),
        },
        Metric {
            readme: "src/arithmetic/u32/README.md",
            key: "u32_lessthan_stack",
            value: max_stack_items(
                script! {
                    { u32::stack::u32_push(1) }
                    { u32::stack::u32_push(2) }
                    { u32::cmp::u32_lessthan() }
                },
                vec![],
            ),
        },
        Metric {
            readme: "src/arithmetic/u32/README.md",
            key: "u32_lessthanorequal",
            value: script_len(u32::cmp::u32_lessthanorequal()),
        },
        Metric {
            readme: "src/arithmetic/u32/README.md",
            key: "u32_lessthanorequal_stack",
            value: max_stack_items(
                script! {
                    { u32::stack::u32_push(1) }
                    { u32::stack::u32_push(1) }
                    { u32::cmp::u32_lessthanorequal() }
                },
                vec![],
            ),
        },
        Metric {
            readme: "src/arithmetic/u32/README.md",
            key: "u32_or",
            value: script_len(u32::or::u32_or(0, 1, 3)),
        },
        Metric {
            readme: "src/arithmetic/u32/README.md",
            key: "u32_or_stack",
            value: max_stack_items(
                script! {
                    { u32::xor::u8_push_xor_table() }
                    { u32::stack::u32_push(0x0123_4567) }
                    { u32::stack::u32_push(0x89ab_cdef) }
                    { u32::or::u32_or(0, 1, 3) }
                    { u32::stack::u32_drop() }
                    { u32::stack::u32_drop() }
                    { u32::xor::u8_drop_xor_table() }
                    OP_1
                },
                vec![],
            ),
        },
        Metric {
            readme: "src/arithmetic/u32/README.md",
            key: "u32_notequal",
            value: script_len(u32::stack::u32_notequal()),
        },
        Metric {
            readme: "src/arithmetic/u32/README.md",
            key: "u32_notequal_stack",
            value: max_stack_items(
                script! {
                    { u32::stack::u32_push(0) }
                    { u32::stack::u32_push(1) }
                    { u32::stack::u32_notequal() }
                },
                vec![],
            ),
        },
        Metric {
            readme: "src/arithmetic/u32/README.md",
            key: "u8_logic_table_push",
            value: script_len(u32::xor::u8_push_xor_table()),
        },
        Metric {
            readme: "src/arithmetic/u32/README.md",
            key: "u8_logic_table_drop",
            value: script_len(u32::xor::u8_drop_xor_table()),
        },
        Metric {
            readme: "src/arithmetic/bigint/README.md",
            key: "u254_add",
            value: script_len(U254::add(1, 0)),
        },
        Metric {
            readme: "src/arithmetic/bigint/README.md",
            key: "u254_mul",
            value: script_len(U254::mul()),
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "rns_add",
            value: script_len(rns_add),
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "rns_sub",
            value: script_len(rns_sub),
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "rns_mul",
            value: script_len(rns_mul),
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_add",
            value: script_len(prime_rns_add),
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_add_stack",
            value: max_stack_items(
                script! {
                    { rns::prime::push_value(&prime_rns_max) }
                    { rns::prime::push_value(&prime_rns_rhs) }
                    { rns::prime::add() }
                    { rns::prime::from_altstack() }
                    { rns::prime::drop_value() }
                    OP_TRUE
                },
                vec![],
            ),
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_sub",
            value: script_len(prime_rns_sub),
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_sub_stack",
            value: max_stack_items(
                script! {
                    { rns::prime::push_value(&prime_rns_max) }
                    { rns::prime::push_value(&prime_rns_rhs) }
                    { rns::prime::sub() }
                    { rns::prime::from_altstack() }
                    { rns::prime::drop_value() }
                    OP_TRUE
                },
                vec![],
            ),
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_centered_add",
            value: script_len(prime_rns_centered_add),
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_centered_add_stack",
            value: max_stack_items(
                script! {
                    { rns::prime::push_centered_value(&prime_rns_centered_lhs) }
                    { rns::prime::push_centered_value(&prime_rns_centered_rhs) }
                    { rns::prime::add_centered() }
                    { rns::prime::from_altstack() }
                    { rns::prime::drop_value() }
                    OP_TRUE
                },
                vec![],
            ),
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_centered_sub",
            value: script_len(prime_rns_centered_sub),
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_centered_sub_stack",
            value: max_stack_items(
                script! {
                    { rns::prime::push_centered_value(&prime_rns_centered_lhs) }
                    { rns::prime::push_centered_value(&prime_rns_centered_rhs) }
                    { rns::prime::sub_centered() }
                    { rns::prime::from_altstack() }
                    { rns::prime::drop_value() }
                    OP_TRUE
                },
                vec![],
            ),
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_mul",
            value: script_len(prime_rns_mul.clone()),
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_mul_table_push",
            value: prime_rns_mul_cost.table_push,
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_mul_table_drop",
            value: prime_rns_mul_cost.table_drop,
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_mul_computation",
            value: prime_rns_mul_cost.computation,
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_mul_stack",
            value: max_stack_items(
                script! {
                    { rns::prime::push_value(&prime_rns_max) }
                    { rns::prime::push_value(&prime_rns_rhs) }
                    { rns::prime::mul(0) }
                    { rns::prime::from_altstack() }
                    { rns::prime::drop_value() }
                    OP_TRUE
                },
                vec![],
            ),
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_mul_opcodes",
            value: prime_rns_mul_opcodes,
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_mul_batch_6",
            value: script_len(prime_rns_batch_mul.clone()),
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_mul_batch_6_raw",
            value: prime_rns_batch_cost.total(),
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_mul_batch_6_table_push",
            value: prime_rns_batch_cost.table_push,
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_mul_batch_6_table_drop",
            value: prime_rns_batch_cost.table_drop,
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_mul_batch_6_arithmetic",
            value: prime_rns_batch_cost.arithmetic,
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_mul_batch_6_routing",
            value: prime_rns_batch_cost.routing_output,
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_mul_batch_6_output_restore",
            value: (rns::prime::RESIDUE_COUNT * prime_rns_batch_products) as usize,
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_mul_batch_6_stack",
            value: max_stack_items(
                script! {
                    { rns::prime::batch::mul(prime_rns_batch_products, 0) }
                    for _ in 0..rns::prime::RESIDUE_COUNT * prime_rns_batch_products {
                        OP_FROMALTSTACK OP_DROP
                    }
                    OP_TRUE
                },
                prime_rns_batch_input_items,
            ),
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_hinted_mod_mul",
            value: script_len(prime_rns_hinted_mul.clone()),
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_hinted_mod_mul_table_push",
            value: prime_rns_hinted_mul_cost.table_push,
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_hinted_mod_mul_table_drop",
            value: prime_rns_hinted_mul_cost.table_drop,
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_hinted_mod_mul_computation",
            value: prime_rns_hinted_mul_cost.computation,
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_hinted_mod_mul_opcodes",
            value: prime_rns_hinted_mul_opcodes,
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_hinted_mod_mul_witness",
            value: witness_size(&prime_rns_hinted_hint_items),
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_hinted_mod_mul_stack",
            value: max_stack_items(
                script! {
                    { prime_rns_hinted_mul }
                    { rns::prime::drop_value() }
                    OP_TRUE
                },
                prime_rns_hinted_input_items,
            ),
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_carry_hinted_mod_mul",
            value: script_len(prime_rns_carry_hinted_mul.clone()),
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_carry_hinted_mod_mul_table_push",
            value: prime_rns_carry_hinted_mul_cost.table_push,
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_carry_hinted_mod_mul_table_drop",
            value: prime_rns_carry_hinted_mul_cost.table_drop,
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_carry_hinted_mod_mul_computation",
            value: prime_rns_carry_hinted_mul_cost.computation,
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_carry_hinted_mod_mul_opcodes",
            value: prime_rns_carry_hinted_mul_opcodes,
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_carry_hinted_mod_mul_witness",
            value: witness_size(&prime_rns_carry_hinted_hint_items),
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_carry_hinted_mod_mul_stack",
            value: max_stack_items(
                script! {
                    { prime_rns_carry_hinted_mul }
                    { rns::prime::carry::drop_value() }
                    OP_TRUE
                },
                prime_rns_carry_hinted_input_items,
            ),
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_bound_carry_hinted_mod_mul",
            value: script_len(prime_rns_bound_carry_mul.clone()),
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_bound_carry_hinted_mod_mul_table_push",
            value: prime_rns_bound_carry_cost.table_push,
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_bound_carry_hinted_mod_mul_table_drop",
            value: prime_rns_bound_carry_cost.table_drop,
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_bound_carry_hinted_mod_mul_range_checks",
            value: prime_rns_bound_carry_cost.range_checks,
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_bound_carry_hinted_mod_mul_residue_binding",
            value: prime_rns_bound_carry_cost.residue_binding,
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_bound_carry_hinted_mod_mul_modular_relation",
            value: prime_rns_bound_carry_cost.modular_relation,
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_bound_carry_hinted_mod_mul_routing_output",
            value: prime_rns_bound_carry_cost.routing_output,
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_bound_carry_hinted_mod_mul_opcodes",
            value: prime_rns_bound_carry_opcodes,
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_bound_carry_hinted_mod_mul_witness",
            value: witness_size(&prime_rns_bound_carry_input_items),
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_bound_carry_hinted_mod_mul_stack",
            value: max_stack_items(
                script! {
                    { prime_rns_bound_carry_mul }
                    for _ in 0..bound::LIMB_COUNT + bound::RESIDUE_COUNT {
                        OP_DROP
                    }
                    OP_TRUE
                },
                prime_rns_bound_carry_input_items,
            ),
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_bind_value",
            value: script_len(prime_rns_bind_value),
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_bind_value_below",
            value: script_len(prime_rns_bind_value_below),
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_bind_value_validation",
            value: prime_rns_bind_value_cost.limb_validation,
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_bind_value_binding",
            value: prime_rns_bind_value_cost.residue_binding,
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_bind_value_routing",
            value: prime_rns_bind_value_cost.routing_output,
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_composable_hinted_mod_mul",
            value: script_len(prime_rns_composable_mul.clone()),
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_composable_hinted_mod_mul_table_push",
            value: prime_rns_composable_cost.table_push,
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_composable_hinted_mod_mul_table_drop",
            value: prime_rns_composable_cost.table_drop,
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_composable_hinted_mod_mul_validation",
            value: prime_rns_composable_cost.field_validation,
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_composable_hinted_mod_mul_quotient_binding",
            value: prime_rns_composable_cost.quotient_binding,
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_composable_hinted_mod_mul_remainder_binding",
            value: prime_rns_composable_cost.remainder_binding,
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_composable_hinted_mod_mul_modular_relation",
            value: prime_rns_composable_cost.modular_relation,
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_composable_hinted_mod_mul_routing_output",
            value: prime_rns_composable_cost.routing_output,
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_composable_hinted_mod_mul_opcodes",
            value: prime_rns_composable_opcodes,
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_composable_hinted_mod_mul_witness",
            value: witness_size(&prime_rns_composable_hint_items),
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_composable_hinted_mod_mul_stack",
            value: max_stack_items(
                script! {
                    { prime_rns_composable_mul }
                    for _ in 0..composable::RESIDUE_COUNT {
                        OP_DROP
                    }
                    OP_TRUE
                },
                prime_rns_composable_input_items,
            ),
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_composable_bind_value",
            value: script_len(prime_rns_composable_bind.clone()),
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_composable_bind_value_validation",
            value: prime_rns_composable_bind_cost.limb_and_field_validation,
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_composable_bind_value_binding",
            value: prime_rns_composable_bind_cost.residue_binding,
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_composable_bind_value_routing",
            value: prime_rns_composable_bind_cost.routing_output,
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_composable_bind_value_opcodes",
            value: prime_rns_composable_bind_opcodes,
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_composable_bind_value_witness",
            value: witness_size(&prime_rns_composable_bind_items),
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_composable_bind_value_stack",
            value: max_stack_items(
                script! {
                    { prime_rns_composable_bind }
                    for _ in 0..composable::RESIDUE_COUNT {
                        OP_DROP
                    }
                    OP_TRUE
                },
                prime_rns_composable_bind_items,
            ),
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_mul_witness",
            value: witness_size(&prime_rns_operand_items),
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_mul_witness_max",
            value: witness_size(&prime_rns_worst_operand_items),
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_verify",
            value: script_len(prime_rns_verify),
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_verify_witness",
            value: witness_size(&prime_rns_max_value_items),
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_verify_witness_max",
            value: witness_size(&prime_rns_worst_value_items),
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "prime_rns_verify_stack",
            value: max_stack_items(
                script! {
                    { rns::prime::push_value(&prime_rns_max) }
                    { rns::prime::verify_canonical() }
                    { rns::prime::drop_value() }
                    OP_TRUE
                },
                vec![],
            ),
        },
        Metric {
            readme: "src/arithmetic/scriptint/README.md",
            key: "scriptint_mul_constant_13",
            value: script_len(scriptint::mul_by_constant(13)),
        },
        Metric {
            readme: "src/arithmetic/scriptint/README.md",
            key: "scriptint_mul_witness_min",
            value: witness_size(&[Vec::new()]),
        },
        Metric {
            readme: "src/arithmetic/scriptint/README.md",
            key: "scriptint_mul_witness_max",
            value: witness_size(&[scriptnum(2_147_483_647)]),
        },
        Metric {
            readme: "src/arithmetic/scriptint/README.md",
            key: "scriptint_mul_stack",
            value: max_stack_items(scriptint::mul_by_constant(13), vec![scriptnum(7)]),
        },
        Metric {
            readme: "src/arithmetic/scriptint/README.md",
            key: "scriptint_div_rem_8",
            value: script_len(scriptint::hinted_div_rem(8)),
        },
        Metric {
            readme: "src/arithmetic/scriptint/README.md",
            key: "scriptint_div_8",
            value: script_len(scriptint::hinted_div(8)),
        },
        Metric {
            readme: "src/arithmetic/scriptint/README.md",
            key: "scriptint_rem_8",
            value: script_len(scriptint::hinted_rem(8)),
        },
        Metric {
            readme: "src/arithmetic/scriptint/README.md",
            key: "scriptint_div_witness_min",
            value: witness_size(&[Vec::new(), Vec::new()]),
        },
        Metric {
            readme: "src/arithmetic/scriptint/README.md",
            key: "scriptint_div_witness_max",
            value: witness_size(&[scriptnum(2_147_483_647), scriptnum(2_147_483_647)]),
        },
        Metric {
            readme: "src/arithmetic/scriptint/README.md",
            key: "scriptint_div_rem_stack",
            value: max_stack_items(
                script! {
                    { scriptint::hinted_div_rem(8) }
                    OP_2DROP OP_1
                },
                division_witness,
            ),
        },
        Metric {
            readme: "src/arithmetic/u31/README.md",
            key: "u31_add",
            value: script_len(u31::u31_add::<u31::M31>()),
        },
        Metric {
            readme: "src/arithmetic/u31/README.md",
            key: "u31_sub",
            value: script_len(u31::u31_sub::<u31::M31>()),
        },
        Metric {
            readme: "src/arithmetic/u31/README.md",
            key: "u31_mul",
            value: script_len(u31::u31_mul::<u31::M31>()),
        },
        Metric {
            readme: "src/arithmetic/u31/README.md",
            key: "u31_mul_constant",
            value: script_len(u31::u31_mul_by_constant::<u31::M31>(0x1234_5678)),
        },
        Metric {
            readme: "src/arithmetic/fields/README.md",
            key: "f257_mul_baseline",
            value: script_len(u31::u31_mul::<f257::F257>()),
        },
        Metric {
            readme: "src/arithmetic/fields/README.md",
            key: "f257_mul_compact",
            value: script_len(u31::u31_mul_compact::<f257::F257>()),
        },
        Metric {
            readme: "src/arithmetic/fields/README.md",
            key: "f257_mul_compact_stack",
            value: max_stack_items(
                u31::u31_mul_compact::<f257::F257>(),
                vec![scriptnum(256), scriptnum(256)],
            ),
        },
        Metric {
            readme: "src/arithmetic/fields/README.md",
            key: "f257_mul_centered_173",
            value: script_len(u31::u31_mul_by_constant_centered::<f257::F257>(173)),
        },
        Metric {
            readme: "src/arithmetic/fields/README.md",
            key: "f257_mul_centered_stack",
            value: max_stack_items(
                u31::u31_mul_by_constant_centered::<f257::F257>(173),
                vec![scriptnum(256)],
            ),
        },
        Metric {
            readme: "src/arithmetic/fields/README.md",
            key: "f257_full_lookup_batch8",
            value: script_len(u31::u31_mul_by_constant_lookup_batch::<f257::F257>(173, 8)),
        },
        Metric {
            readme: "src/arithmetic/fields/README.md",
            key: "f257_full_lookup_batch8_stack",
            value: max_stack_items(
                script! {
                    { u31::u31_mul_by_constant_lookup_batch::<f257::F257>(173, 8) }
                    for _ in 0..4 {
                        OP_2DROP
                    }
                    OP_TRUE
                },
                vec![scriptnum(256); 8],
            ),
        },
        Metric {
            readme: "src/arithmetic/fields/README.md",
            key: "f257_half_lookup_batch8",
            value: script_len(u31::u31_mul_by_constant_half_lookup_batch::<f257::F257>(
                173, 8,
            )),
        },
        Metric {
            readme: "src/arithmetic/fields/README.md",
            key: "f257_half_lookup_batch8_stack",
            value: max_stack_items(
                script! {
                    { u31::u31_mul_by_constant_half_lookup_batch::<f257::F257>(173, 8) }
                    for _ in 0..4 {
                        OP_2DROP
                    }
                    OP_TRUE
                },
                vec![scriptnum(256); 8],
            ),
        },
        Metric {
            readme: "src/arithmetic/fields/README.md",
            key: "f257_log_memory",
            value: script_len(f257_log_memory),
        },
        Metric {
            readme: "src/arithmetic/fields/README.md",
            key: "f257_log_constant_query",
            value: script_len(f257::mul_by_constant_from_log_tables(173, 511)),
        },
        Metric {
            readme: "src/arithmetic/fields/README.md",
            key: "f257_log_constant_stack",
            value: max_stack_items(f257_log_constant_state_script, vec![]),
        },
        Metric {
            readme: "src/arithmetic/fields/README.md",
            key: "f257_log_variable_query",
            value: script_len(f257::mul_from_log_tables(510)),
        },
        Metric {
            readme: "src/arithmetic/fields/README.md",
            key: "f257_log_state_stack",
            value: max_stack_items(f257_log_state_script, vec![]),
        },
        Metric {
            readme: "src/arithmetic/fields/README.md",
            key: "f257_square_memory",
            value: script_len(f257_square_memory),
        },
        Metric {
            readme: "src/arithmetic/fields/README.md",
            key: "f257_square_query",
            value: script_len(f257::square_from_table(511)),
        },
        Metric {
            readme: "src/arithmetic/fields/README.md",
            key: "f257_square_state_stack",
            value: max_stack_items(f257_square_state_script, vec![]),
        },
        Metric {
            readme: "src/arithmetic/fields/README.md",
            key: "f12289_mul_compact",
            value: script_len(u31::u31_mul_compact::<f12289::F12289>()),
        },
        Metric {
            readme: "src/arithmetic/fields/README.md",
            key: "f12289_mul_compact_stack",
            value: max_stack_items(
                u31::u31_mul_compact::<f12289::F12289>(),
                vec![scriptnum(12_288), scriptnum(12_288)],
            ),
        },
        Metric {
            readme: "src/arithmetic/fields/README.md",
            key: "f12289_radix128_memory",
            value: script_len(f12289_radix128_memory),
        },
        Metric {
            readme: "src/arithmetic/fields/README.md",
            key: "f12289_radix128_query",
            value: script_len(f12289::mul_by_constant_from_radix_tables(7, 511)),
        },
        Metric {
            readme: "src/arithmetic/fields/README.md",
            key: "f12289_radix128_state_stack",
            value: max_stack_items(f12289_radix128_state_script, vec![]),
        },
        Metric {
            readme: "src/arithmetic/u31/README.md",
            key: "u31_witness_min",
            value: witness_size(&vec![Vec::new(); 2]),
        },
        Metric {
            readme: "src/arithmetic/u31/README.md",
            key: "u31_witness_max",
            value: witness_size(&vec![vec![1; 4]; 2]),
        },
        Metric {
            readme: "src/arithmetic/u31/README.md",
            key: "qm31_add",
            value: script_len(u31::u31ext_add::<u31::QM31>()),
        },
        Metric {
            readme: "src/arithmetic/u31/README.md",
            key: "qm31_sub",
            value: script_len(u31::u31ext_sub::<u31::QM31>()),
        },
        Metric {
            readme: "src/arithmetic/u31/README.md",
            key: "qm31_mul",
            value: script_len(u31::u31ext_mul::<u31::QM31>()),
        },
        Metric {
            readme: "src/arithmetic/u31/README.md",
            key: "babybear4_mul",
            value: script_len(u31::u31ext_mul::<u31::BabyBear4>()),
        },
        Metric {
            readme: "src/arithmetic/u31/README.md",
            key: "qm31_mul_base",
            value: script_len(u31::u31ext_mul_u31::<u31::QM31>()),
        },
        Metric {
            readme: "src/arithmetic/u31/README.md",
            key: "qm31_mul_constant",
            value: script_len(u31::u31ext_mul_u31_by_constant::<u31::QM31>(0x1234_5678)),
        },
        Metric {
            readme: "src/arithmetic/u31/README.md",
            key: "u31ext_witness_min",
            value: witness_size(&vec![Vec::new(); 8]),
        },
        Metric {
            readme: "src/arithmetic/u31/README.md",
            key: "u31ext_witness_max",
            value: witness_size(&vec![vec![1; 4]; 8]),
        },
        Metric {
            readme: "src/hashes/ripemd160/README.md",
            key: "ripemd160_u32_32",
            value: script_len(ripemd160::ripemd160(32)),
        },
        Metric {
            readme: "src/hashes/sha1/README.md",
            key: "sha1_u32_32",
            value: script_len(sha1::sha1(32)),
        },
        Metric {
            readme: "src/hashes/sha256/README.md",
            key: "sha2_u32_32",
            value: script_len(sha256::sha2_u32::sha256(32)),
        },
        Metric {
            readme: "src/hashes/sha256/README.md",
            key: "sha2_u4_32",
            value: script_len(sha256::sha2_u4::sha256(32)),
        },
        Metric {
            readme: "src/hashes/shake256/README.md",
            key: "shake256_32_1024",
            value: script_len(shake256::shake256(32)),
        },
        Metric {
            readme: "src/hashes/shake256/README.md",
            key: "shake256_witness_32",
            value: witness_size(&vec![vec![0x42]; 32]),
        },
        Metric {
            readme: "src/hashes/shake256/README.md",
            key: "shake256_stack_32_1024",
            value: max_stack_items(
                script! {
                    { shake256::shake256(32) }
                    for _ in 0..(shake256::OUTPUT_LEN / 2) {
                        OP_2DROP
                    }
                    OP_TRUE
                },
                vec![vec![0x42]; 32],
            ),
        },
        Metric {
            readme: "src/hashes/blake3/README.md",
            key: "blake3_64_limb29",
            value: blake3::blake3_compute_script_with_limb(64, 29)
                .compile()
                .len(),
        },
        Metric {
            readme: "src/commitments/README.md",
            key: "hash_path_integer_31",
            value: script_len(verify_hash_path_to_integer(31, hash_path_commitment)),
        },
        Metric {
            readme: "src/commitments/README.md",
            key: "hash_path_integer_witness_31",
            value: witness_size(&hash_path_witness),
        },
        Metric {
            readme: "src/commitments/README.md",
            key: "hash_path_integer_stack_31",
            value: max_stack_items(
                verify_hash_path_to_integer(31, hash_path_commitment),
                hash_path_witness,
            ),
        },
        Metric {
            readme: "src/commitments/README.md",
            key: "four_way_hash_path_integer_31",
            value: script_len(verify_four_way_hash_path_to_integer(
                31,
                four_way_hash_path_commitment,
            )),
        },
        Metric {
            readme: "src/commitments/README.md",
            key: "four_way_hash_path_integer_witness_31",
            value: witness_size(&four_way_hash_path_witness),
        },
        Metric {
            readme: "src/commitments/README.md",
            key: "four_way_hash_path_integer_stack_31",
            value: max_stack_items(
                verify_four_way_hash_path_to_integer(31, four_way_hash_path_commitment),
                four_way_hash_path_witness,
            ),
        },
        Metric {
            readme: "src/commitments/README.md",
            key: "preimage_length_default",
            value: script_len(verify_preimage_length(length_commitment)),
        },
        Metric {
            readme: "src/commitments/README.md",
            key: "preimage_length_witness_min",
            value: witness_size(&[vec![0; 16]]),
        },
        Metric {
            readme: "src/commitments/README.md",
            key: "preimage_length_witness_max",
            value: witness_size(&[vec![0; 520]]),
        },
        Metric {
            readme: "src/commitments/README.md",
            key: "preimage_length_stack",
            value: max_stack_items(
                verify_preimage_length(length_commitment),
                vec![length_preimage],
            ),
        },
        Metric {
            readme: "src/signatures/lamport/README.md",
            key: "lamport_lock",
            value: script_len(lamport::lamport_2bit_commit(h0, h1, h2, h3)),
        },
        Metric {
            readme: "src/signatures/lamport/README.md",
            key: "lamport_witness",
            value: witness_size(&lamport_witness),
        },
        Metric {
            readme: "src/signatures/hors/README.md",
            key: "hors_lock_n32_t8",
            value: script_len(hors::hors_locking_script(&hors_public_keys, 8)),
        },
        Metric {
            readme: "src/signatures/hors/README.md",
            key: "hors_witness_n32_t8",
            value: witness_size(&hors_witness),
        },
        Metric {
            readme: "src/signatures/winternitz/README.md",
            key: "wots32_lock",
            value: script_len(Wots32::checksig_verify(&wots_public_key)),
        },
        Metric {
            readme: "src/signatures/winternitz/README.md",
            key: "wots32_witness",
            value: serialize(&wots_witness).len(),
        },
        Metric {
            readme: "src/ciphers/prince/README.md",
            key: "prince_encrypt",
            value: script_len(prince::prince_encrypt(0)),
        },
        Metric {
            readme: "src/ciphers/prince/README.md",
            key: "prince_witness_min",
            value: witness_size(&vec![Vec::new(); 16]),
        },
        Metric {
            readme: "src/ciphers/prince/README.md",
            key: "prince_witness_max",
            value: witness_size(&vec![vec![1]; 16]),
        },
        Metric {
            readme: "src/ciphers/aes/README.md",
            key: "aes128_encrypt",
            value: script_len(aes::aes128_encrypt(aes_zero_key)),
        },
        Metric {
            readme: "src/ciphers/aes/README.md",
            key: "aes128_witness_min",
            value: witness_size(&vec![Vec::new(); 32]),
        },
        Metric {
            readme: "src/ciphers/aes/README.md",
            key: "aes128_witness_max",
            value: witness_size(&vec![vec![1]; 32]),
        },
        Metric {
            readme: "src/ciphers/aes/README.md",
            key: "aes128_stack",
            value: max_stack_items(aes_stack_script, vec![Vec::new(); 32]),
        },
        Metric {
            readme: "src/curves/bn254/fields/README.md",
            key: "fq_add",
            value: script_len(Fq::add(1, 0)),
        },
        Metric {
            readme: "src/curves/bn254/fields/README.md",
            key: "fr_add",
            value: script_len(Fr::add(1, 0)),
        },
        Metric {
            readme: "src/curves/bn254/fields/README.md",
            key: "fq2_add",
            value: script_len(Fq2::add(2, 0)),
        },
        Metric {
            readme: "src/curves/bn254/groups/README.md",
            key: "g1_is_zero",
            value: script_len(G1Affine::is_zero()),
        },
        Metric {
            readme: "src/curves/bn254/groups/README.md",
            key: "g2_is_zero",
            value: script_len(G2Affine::is_zero_keep_element()),
        },
    ]
}

#[test]
fn readme_metrics_are_current() {
    let update = env::var_os("UPDATE_PRIMITIVE_METRICS").is_some();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));

    for metric in metrics() {
        let path = root.join(metric.readme);
        let contents = fs::read_to_string(&path).unwrap();
        let start = format!("<!-- metric:{} -->", metric.key);
        let end = format!("<!-- /metric:{} -->", metric.key);
        let start_index = contents.find(&start).unwrap_or_else(|| {
            panic!(
                "missing metric marker `{}` in {}",
                metric.key, metric.readme
            )
        });
        let value_start = start_index + start.len();
        let relative_end = contents[value_start..]
            .find(&end)
            .unwrap_or_else(|| panic!("missing closing metric marker `{}`", metric.key));
        let value_end = value_start + relative_end;
        let current = &contents[value_start..value_end];

        if update {
            let mut updated = contents;
            updated.replace_range(value_start..value_end, &metric.value.to_string());
            fs::write(path, updated).unwrap();
        } else {
            assert_eq!(
                current,
                metric.value.to_string(),
                "{} is stale; run UPDATE_PRIMITIVE_METRICS=1 cargo test --test primitive_metrics",
                metric.readme,
            );
        }
    }
}
