//! Garbled mixed-radix decoding with a total modulo-2^width message rule.
//! Child module of the existing membership decoder; not a standalone binary.
//! Honest-garbler correctness only, with the parent's garbling assumptions.
#![allow(dead_code)]
use super::{commitment, Builder, Decoder, Label, Wire};
use num_bigint::BigUint;

fn bits(radix: usize) -> usize {
    assert!(radix >= 2);
    usize::BITS as usize - (radix - 1).leading_zeros() as usize
}

fn constant(b: &Builder, wire: Wire) -> Option<bool> {
    if wire.id == b.zero().id {
        Some(wire.zero != b.zero().zero)
    } else {
        None
    }
}

fn xor(b: &mut Builder, a: Wire, c: Wire) -> Wire {
    match (constant(b, a), constant(b, c)) {
        (Some(false), _) => c,
        (Some(true), _) => b.not(c),
        (_, Some(false)) => a,
        (_, Some(true)) => b.not(a),
        _ if a.id == c.id => {
            if a.zero == c.zero {
                b.zero()
            } else {
                b.not(b.zero())
            }
        }
        _ => b.xor(a, c),
    }
}

fn and(b: &mut Builder, a: Wire, c: Wire) -> Wire {
    match (constant(b, a), constant(b, c)) {
        (Some(false), _) | (_, Some(false)) => b.zero(),
        (Some(true), _) => c,
        (_, Some(true)) => a,
        _ if a.id == c.id => {
            if a.zero == c.zero {
                a
            } else {
                b.zero()
            }
        }
        _ => b.and(a, c),
    }
}

fn shifted(b: &Builder, a: &[Wire], shift: usize, width: usize) -> Vec<Wire> {
    (0..width)
        .map(|i| {
            if i >= shift {
                a.get(i - shift).copied().unwrap_or_else(|| b.zero())
            } else {
                b.zero()
            }
        })
        .collect()
}

fn add(b: &mut Builder, a: &[Wire], c: &[Wire], width: usize, subtract: bool) -> Vec<Wire> {
    let mut carry = if subtract { b.not(b.zero()) } else { b.zero() };
    let mut result = Vec::with_capacity(width);
    for i in 0..width {
        let ai = a.get(i).copied().unwrap_or_else(|| b.zero());
        let mut ci = c.get(i).copied().unwrap_or_else(|| b.zero());
        if subtract {
            ci = b.not(ci);
        }
        let ac = xor(b, ai, ci);
        result.push(xor(b, ac, carry));
        if i + 1 != width {
            // majority(a,c,carry) = a XOR ((a XOR c) AND (a XOR carry)).
            // One AND per full-adder carry; the discarded top carry is absent.
            let ai_carry = xor(b, ai, carry);
            let term = and(b, ac, ai_carry);
            carry = xor(b, ai, term);
        }
    }
    result
}

fn multiply(b: &mut Builder, a: &[Wire], radix: usize, width: usize) -> Vec<Wire> {
    if radix == 230_300 {
        // 230300 = 4 * 7 * (2^13 + 2^5 + 1): three additions/subtractions.
        // Discarding the high two bits before the final shift is exact mod 2^w.
        if width <= 2 {
            return vec![b.zero(); width];
        }
        let inner = width - 2;
        let shifted_three = shifted(b, a, 3, inner);
        let seven = add(b, &shifted_three, a, inner, true);
        let high = shifted(b, &seven, 13, inner);
        let middle = shifted(b, &seven, 5, inner);
        let partial = add(b, &high, &middle, inner, false);
        let product = add(b, &partial, &seven, inner, false);
        shifted(b, &product, 2, width)
    } else if radix == 3_162_510 {
        // C(54,5) = 130 * (2^15 - 2^13 - 2^8 + 2^3 - 1).
        // Five additions/subtractions, then a free left shift, modulo 2^width.
        if width <= 1 {
            return vec![b.zero(); width];
        }
        let inner = width - 1;
        let high = shifted(b, a, 6, inner);
        let sixty_five = add(b, &high, a, inner, false);
        let high = shifted(b, &sixty_five, 15, inner);
        let sub = shifted(b, &sixty_five, 13, inner);
        let product = add(b, &high, &sub, inner, true);
        let sub = shifted(b, &sixty_five, 8, inner);
        let product = add(b, &product, &sub, inner, true);
        let term = shifted(b, &sixty_five, 3, inner);
        let product = add(b, &product, &term, inner, false);
        let product = add(b, &product, &sixty_five, inner, true);
        shifted(b, &product, 1, width)
    } else {
        let mut out = vec![b.zero(); width];
        for j in 0..usize::BITS as usize {
            if radix >> j & 1 != 0 && j < width {
                let term = shifted(b, a, j, width);
                out = add(b, &out, &term, width, false);
            }
        }
        out
    }
}

fn less_than(b: &mut Builder, a: &[Wire], radix: usize) -> Wire {
    if radix.is_power_of_two() {
        return b.not(b.zero());
    }
    let mut less = b.zero();
    for (i, &ai) in a.iter().enumerate() {
        less = if radix >> i & 1 == 1 {
            let not_less = b.not(less);
            let greater_or_equal = and(b, ai, not_less);
            b.not(greater_or_equal)
        } else {
            let not_ai = b.not(ai);
            and(b, not_ai, less)
        };
    }
    less
}

/// Garbler-only wiring helper: both input labels (hence secret Delta) are
/// required. It never adds both output labels to the public Decoder object.
pub(crate) fn private_output_pairs(gc: &Decoder, input_pairs: &[[Label; 2]]) -> Vec<[Label; 2]> {
    assert_eq!(input_pairs.len(), gc.n);
    let delta = input_pairs[0][0] ^ input_pairs[0][1];
    assert!(input_pairs.iter().all(|p| p[0] ^ p[1] == delta));
    let selected: Vec<_> = input_pairs.iter().map(|p| p[0]).collect();
    gc.evaluate(&selected)
        .unwrap()
        .iter()
        .zip(&gc.output_commitments)
        .map(|(&label, c)| {
            let opposite = label ^ delta;
            if commitment(label) == c[0] {
                assert_eq!(commitment(opposite), c[1]);
                [label, opposite]
            } else {
                assert_eq!(commitment(label), c[1]);
                assert_eq!(commitment(opposite), c[0]);
                [opposite, label]
            }
        })
        .collect()
}

/// Inputs are grouped by pool: little-endian rank bits, then one validity bit.
/// Pool zero is the least significant digit. Public outputs are message bits
/// (little endian) and the conjunction of all rank bounds and validity flags.
pub(crate) fn build(
    tag: usize,
    input_pairs: &[[Label; 2]],
    radices: &[usize],
    width: usize,
    private_seed: [u8; 32],
) -> Decoder {
    assert!(!radices.is_empty() && width > 0);
    assert_eq!(
        input_pairs.len(),
        radices.iter().map(|&r| bits(r) + 1).sum::<usize>()
    );
    let mut b = Builder::new(tag, input_pairs, private_seed);
    let mut digits = vec![];
    let mut cursor = 1;
    let mut valid = b.not(b.zero());
    for &radix in radices {
        let width = bits(radix);
        let digit = b.wires[cursor..cursor + width].to_vec();
        let in_range = less_than(&mut b, &digit, radix);
        valid = and(&mut b, valid, in_range);
        let supplied_valid = b.wires[cursor + width];
        valid = and(&mut b, valid, supplied_valid);
        digits.push(digit);
        cursor += width + 1;
    }
    let modulus = BigUint::from(1u8) << width;
    let mut bound = BigUint::from(1u8);
    let mut accumulator = vec![];
    for i in (0..radices.len()).rev() {
        bound = (&bound * radices[i]).min(modulus.clone());
        let active = (&bound - BigUint::from(1u8)).bits().max(1) as usize;
        accumulator = multiply(&mut b, &accumulator, radices[i], active);
        accumulator = add(&mut b, &accumulator, &digits[i], active, false);
    }
    accumulator.resize(width, b.zero());
    for bit in accumulator {
        b.output(bit);
    }
    b.output(valid);
    b.circuit
}

pub(crate) fn decode_bytes(
    gc: &Decoder,
    labels: &[Label],
    width: usize,
) -> Option<(Vec<u8>, bool)> {
    if labels.len() != width + 1 || gc.output_commitments.len() != width + 1 {
        return None;
    }
    let mut bytes = vec![0; width.div_ceil(8)];
    let mut valid = false;
    for (i, (&label, c)) in labels.iter().zip(&gc.output_commitments).enumerate() {
        let bit = if commitment(label) == c[0] {
            false
        } else if commitment(label) == c[1] {
            true
        } else {
            return None;
        };
        if i == width {
            valid = bit;
        } else if bit {
            bytes[i / 8] |= 1 << (i % 8);
        }
    }
    bytes.reverse();
    Some((bytes, valid))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(n: usize) -> Vec<[Label; 2]> {
        (0..n)
            .map(|i| {
                let z = super::super::private_label(&[81; 32], i);
                [z, z ^ 0xabcdef0123456789]
            })
            .collect()
    }
    fn inputs(
        pairs: &[[Label; 2]],
        radices: &[usize],
        values: &[usize],
        valid: &[bool],
    ) -> Vec<Label> {
        let mut out = vec![];
        let mut cursor = 0;
        for (i, &r) in radices.iter().enumerate() {
            for bit in 0..bits(r) {
                out.push(pairs[cursor][values[i] >> bit & 1]);
                cursor += 1;
            }
            out.push(pairs[cursor][usize::from(valid[i])]);
            cursor += 1;
        }
        out
    }
    #[test]
    fn all_small_codewords_are_total_with_explicit_invalid_digit_and_flag_checks() {
        let radices = [6, 10, 3];
        let width = 5;
        let p = pairs(radices.iter().map(|&r| bits(r) + 1).sum());
        let gc = build(997, &p, &radices, width, [3; 32]);
        for a in 0..8 {
            for b in 0..16 {
                for c in 0..4 {
                    let v = [a, b, c];
                    let chosen = inputs(&p, &radices, &v, &[true; 3]);
                    let (decoded, valid) =
                        decode_bytes(&gc, &gc.evaluate(&chosen).unwrap(), width).unwrap();
                    assert_eq!(valid, a < 6 && b < 10 && c < 3);
                    if valid {
                        assert_eq!(decoded, vec![((a + 6 * b + 60 * c) % 32) as u8]);
                    }
                }
            }
        }
        for flag in 0..3 {
            let mut flags = [true; 3];
            flags[flag] = false;
            let chosen = inputs(&p, &radices, &[1, 2, 1], &flags);
            assert!(
                !decode_bytes(&gc, &gc.evaluate(&chosen).unwrap(), width)
                    .unwrap()
                    .1
            );
        }
        let chosen = inputs(&p, &radices, &[1, 2, 1], &[true; 3]);
        let mut output = gc.evaluate(&chosen).unwrap();
        output[0] ^= 1;
        assert!(decode_bytes(&gc, &output, width).is_none());
    }
    #[test]
    fn optimized_radix_product_matches_integer_arithmetic_through_wraparound() {
        let radices = [230_300, 230_300];
        let width = 19;
        let p = pairs(38);
        let gc = build(998, &p, &radices, width, [4; 32]);
        for a in [0, 1, 255, 131071, 230299] {
            for c in [0, 1, 7, 4095, 230299] {
                let chosen = inputs(&p, &radices, &[a, c], &[true; 2]);
                let (output, valid) =
                    decode_bytes(&gc, &gc.evaluate(&chosen).unwrap(), width).unwrap();
                assert!(valid);
                assert_eq!(
                    BigUint::from_bytes_be(&output),
                    BigUint::from((a + 230300 * c) % (1 << width))
                );
            }
        }
    }

    #[test]
    fn round_major_radix_matches_integer_arithmetic_at_truncation_boundaries() {
        let radices = [3_162_510, 3_162_510];
        let p = pairs(46);
        for width in [1, 2, 7, 22, 23, 44] {
            let gc = build(1001, &p, &radices, width, [6; 32]);
            for a in [0usize, 1, 255, (1 << 21) - 1, 3_162_509] {
                for c in [0usize, 1, 255, (1 << 21) - 1, 3_162_509] {
                    let selected = inputs(&p, &radices, &[a, c], &[true; 2]);
                    let (output, valid) =
                        decode_bytes(&gc, &gc.evaluate(&selected).unwrap(), width).unwrap();
                    assert!(valid);
                    assert_eq!(
                        BigUint::from_bytes_be(&output),
                        (BigUint::from(a) + BigUint::from(3_162_510usize) * c)
                            % (BigUint::from(1u8) << width)
                    );
                }
            }
        }
    }

    #[test]
    fn power_of_two_radices_accept_every_representable_digit() {
        let radices = [2, 4];
        let p = pairs(5);
        let gc = build(999, &p, &radices, 3, [5; 32]);
        for a in 0..2 {
            for c in 0..4 {
                let chosen = inputs(&p, &radices, &[a, c], &[true; 2]);
                let (output, valid) = decode_bytes(&gc, &gc.evaluate(&chosen).unwrap(), 3).unwrap();
                assert!(valid);
                assert_eq!(output, vec![(a + 2 * c) as u8]);
            }
        }
    }
}
