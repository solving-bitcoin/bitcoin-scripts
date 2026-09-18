//! Compose the signed-radix-32 decoder with a complete U256 scalar schedule.
//!
//! The schedule consumes 32 canonical signed digits, reconstructs the scalar
//! high-to-low with a real U256 accumulator, and checks the exact result. The
//! table and conditional-branch decoders share that consumer so their byte
//! comparison is like-for-like.

use bitcoin::consensus::encode::serialize;
use bitcoin::Witness;
use bitcoin_lab::{
    arithmetic::{bigint::U256, scriptint, signed_window},
    support::{
        execution::execute_script_with_inputs_strict,
        script::{script, Script, ScriptCompilation},
    },
};
use num_bigint::{BigInt, BigUint};
use num_traits::{One, ToPrimitive};

fn branch_digit_to_altstack() -> Script {
    script! {
        // Canonicality is part of the shared decoder contract.
        OP_DUP OP_DUP 0 OP_ADD OP_EQUALVERIFY
        OP_DUP 0 OP_LESSTHAN
        OP_SWAP OP_ABS OP_SWAP OP_TOALTSTACK
        for bit in (0..5).rev() {
            OP_DUP { 1i64 << bit } OP_GREATERTHANOREQUAL
            OP_IF
                { 1i64 << bit } OP_SUB OP_1
            OP_ELSE
                OP_0
            OP_ENDIF
            OP_TOALTSTACK
        }
        OP_DROP
    }
}

/// Consume one decoder result. The decoder exposes `sign, bit4..bit0` on the
/// altstack, so LIFO consumption sees `bit0..bit4, sign`.
fn consume_signed_digit() -> Script {
    script! {
        OP_FROMALTSTACK
        for weight in [2u32, 4, 8, 16] {
            OP_FROMALTSTACK
            { scriptint::mul_by_constant(weight) }
            OP_ADD
        }
        OP_FROMALTSTACK
        OP_IF
            { U256::push_zero() }
            9 OP_ROLL OP_ADD
            { U256::sub(1, 0) }
        OP_ELSE
            { U256::push_zero() }
            9 OP_ROLL OP_ADD
            { U256::add(1, 0) }
        OP_ENDIF
    }
}

/// Reconstruct a 256-bit scalar from high-to-low signed radix-32 digits.
fn scalar_consumer(digit_count: u32) -> Script {
    script! {
        for _ in 0..digit_count {
            for _ in 0..5 { { U256::double(0) } }
            { consume_signed_digit() }
        }
    }
}

fn table_schedule(digit_count: u32) -> Script {
    script! {
        { signed_window::digits_to_altstack(digit_count, true) }
        { U256::push_zero() }
        { scalar_consumer(digit_count) }
    }
}

fn branch_schedule(digit_count: u32) -> Script {
    script! {
        for _ in 0..digit_count { { branch_digit_to_altstack() } }
        { U256::push_zero() }
        { scalar_consumer(digit_count) }
    }
}

fn signed_digits(mut value: BigUint, digit_count: u32) -> Vec<i64> {
    let mut digits = Vec::with_capacity(digit_count as usize);
    for _ in 0..digit_count - 1 {
        let residue = (&value & BigUint::from(31u32)).to_u32_digits();
        let residue = residue.first().copied().unwrap_or(0);
        value >>= 5usize;
        if residue >= 16 {
            digits.push(i64::from(residue) - 32);
            value += BigUint::one();
        } else {
            digits.push(i64::from(residue));
        }
    }
    digits.push(value.to_i64().expect("top signed digit fits i64"));
    digits
}

fn scalar_from_digits(digits: &[i64]) -> BigUint {
    digits
        .iter()
        .rev()
        .fold(BigInt::ZERO, |value, digit| {
            let value = value << 5usize;
            value + BigInt::from(*digit)
        })
        .to_biguint()
        .expect("signed digits must reconstruct a nonnegative scalar")
}

fn run(label: &str, schedule: Script, witness: Vec<Vec<u8>>, expected: &BigUint) {
    let expected_script = script! {
        { schedule }
        { U256::push_biguint(expected.clone()) }
        { U256::equalverify(1, 0) }
        OP_TRUE
    };
    let compiled = expected_script.clone().compile_with_policy();
    let execution = execute_script_with_inputs_strict(expected_script, witness.clone());
    assert!(
        execution.error.is_none(),
        "{label} strict execution failed: {execution}"
    );
    assert!(execution.success, "{label} rejected the valid scalar");
    assert_eq!(execution.final_stack.len(), 1);
    println!(
        "schedule={label} script_bytes={} witness_bytes={} witness_items={} strict_stack_peak={}",
        compiled.len(),
        serialize(&Witness::from_slice(&witness)).len(),
        witness.len(),
        execution.stats.max_nb_stack_items,
    );
}

fn main() {
    for digit_count in [1u32, 4, 8, 16, 32] {
        let expected = (BigUint::one() << (5 * digit_count as usize - 1)) - BigUint::one();
        let digits = signed_digits(expected.clone(), digit_count);
        assert_eq!(scalar_from_digits(&digits), expected);

        // The executor's first witness item is the bottom of the main stack.
        // The decoder consumes top-down, so present the low digit at the top.
        let witness = digits
            .iter()
            .rev()
            .map(|digit| {
                let mut bytes = [0u8; 8];
                let len = bitcoin::script::write_scriptint(&mut bytes, *digit);
                bytes[..len].to_vec()
            })
            .collect::<Vec<_>>();

        run(
            &format!("shared-table-{digit_count}"),
            table_schedule(digit_count),
            witness.clone(),
            &expected,
        );
        run(
            &format!("conditional-branches-{digit_count}"),
            branch_schedule(digit_count),
            witness,
            &expected,
        );
    }

    let execution = execute_script_with_inputs_strict(table_schedule(1), vec![vec![0x20]]);
    assert!(execution.error.is_some(), "out-of-range digit was accepted");

    let execution = execute_script_with_inputs_strict(table_schedule(1), vec![vec![1, 0]]);
    assert!(execution.error.is_some(), "non-minimal digit was accepted");
}
