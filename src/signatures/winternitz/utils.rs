use crate::script::*;

pub(super) const fn log_base_ceil(n: u32, base: u32) -> u32 {
    let mut res: u32 = 0;
    let mut cur: u64 = 1;
    while cur < (n as u64) {
        cur *= base as u64;
        res += 1;
    }
    res
}

pub(super) fn checksum_to_digits(mut checksum: u32, base: u32, n_digits: u32) -> Vec<u32> {
    debug_assert!((16..=256).contains(&base));
    debug_assert!(
        base.checked_pow(n_digits)
            .map(|upper_limit| checksum < upper_limit)
            .unwrap_or(true),
        "Checksum is too large to fit into the given number of digits"
    );

    let mut digits = vec![0; n_digits as usize];

    for digit in digits.iter_mut().rev() {
        *digit = checksum % base;
        checksum = (checksum - *digit) / base;
    }

    digits
}

pub(crate) fn message_to_digits(n_digits: u32, log2_base: u32, message: &[u8]) -> Vec<u32> {
    debug_assert!((4..=8).contains(&log2_base));
    debug_assert!(
        message.len() as u32 * 8 <= n_digits * log2_base,
        "Message is too long to fit into the given number of digits"
    );

    let mut digits = vec![0u32; n_digits as usize];
    let mut digit_idx: u32 = 0;
    let mut bit_idx: u32 = 0;

    for mut byte in message.iter().copied() {
        for _ in 0..8 {
            if bit_idx == log2_base {
                bit_idx = 0;
                digit_idx += 1;
            }
            digits[digit_idx as usize] |= ((byte & 1) as u32) << bit_idx;
            byte >>= 1;
            bit_idx += 1;
        }
    }

    digits.reverse();
    digits
}

pub fn digits_to_number<const N_DIGITS: usize, const LOG2_BASE: usize>() -> Script {
    script! {
        for _ in 0..N_DIGITS - 1 {
          OP_TOALTSTACK
        }
        for _ in 0..N_DIGITS - 1 {
            for _ in 0..LOG2_BASE {
                OP_DUP OP_ADD
            }
            OP_FROMALTSTACK
            OP_ADD
        }
    }
}

pub fn bitcoin_representation(x: i32) -> Vec<u8> {
    let mut buf = [0u8; 8];
    let len = bitcoin::script::write_scriptint(&mut buf, x as i64);
    return buf[0..len].to_vec();
}
