//! A compact 160-bit constant-sum code over alternating hash-chain stages.
//!
//! This is an experimental, fixed-parameter construction. It authenticates a
//! reversible union of 32,768 constant-composition classes. Fifteen local
//! two-chain relations select one of two equal-sum assignments without witness
//! branch flags. The verifier checks those relations directly, so it does not
//! need a global Script arithmetic checksum.

use crate::support::script::{script, Script};
use bitcoin::{
    hashes::{hash160, ripemd160, sha256, Hash, HashEngine},
    Witness,
};
use core::fmt;
use num_bigint::BigUint;
use num_traits::{One, Zero};
use rand::RngCore;
use std::{collections::HashSet, sync::OnceLock};

const MAX_DIGIT: usize = 45;
const CHAINS: usize = 45;
const IMPLICIT_ENDPOINTS: usize = 12;
const OPENINGS: usize = CHAINS - IMPLICIT_ENDPOINTS;
const FIXED_DIGITS: [u8; 3] = [23, 38, 44];
const PAIRS: [(u8, u8, u8); 15] = [
    (42, 27, 12),
    (39, 17, 4),
    (39, 15, 20),
    (40, 27, 8),
    (27, 41, 2),
    (33, 41, 2),
    (41, 26, 10),
    (21, 5, 12),
    (31, 37, 2),
    (42, 19, 14),
    (43, 25, 8),
    (43, 34, 6),
    (39, 41, 2),
    (13, 29, 12),
    (11, 33, 4),
];
const DOMAIN: &[u8] = b"bitcoin-lab/winternitz20-constant-sum-mixed/v1";

/// A chain node. Alternating stages make intermediate nodes either 20 or 32
/// bytes; the private start is 16 bytes and is never exposed by this geometry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MixedChainValue {
    Start([u8; 16]),
    Narrow([u8; 20]),
    Wide([u8; 32]),
}
impl MixedChainValue {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Start(value) => value,
            Self::Narrow(value) => value,
            Self::Wide(value) => value,
        }
    }
}

/// A consumed one-time signing key. Its source seed must not be restored and reused.
pub struct MixedConstantSumSigningKey20 {
    seed: [u8; 32],
}
impl fmt::Debug for MixedConstantSumSigningKey20 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MixedConstantSumSigningKey20([redacted])")
    }
}

/// Forty-five independent 20-byte endpoints in key-index order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MixedConstantSumPublicKey20 {
    commitments: [[u8; 20]; CHAINS],
}
impl MixedConstantSumPublicKey20 {
    pub fn from_commitments(commitments: [[u8; 20]; CHAINS]) -> Self {
        Self { commitments }
    }
    pub fn commitments(&self) -> &[[u8; 20]; CHAINS] {
        &self.commitments
    }
}

/// Key-indexed digits and nodes plus the selected class in the union code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MixedConstantSumSignature20 {
    nodes: [MixedChainValue; CHAINS],
    digits: [u8; CHAINS],
    class_mask: u16,
}
impl MixedConstantSumSignature20 {
    pub fn digits(&self) -> &[u8; CHAINS] {
        &self.digits
    }
    pub fn chain_values(&self) -> &[MixedChainValue; CHAINS] {
        &self.nodes
    }
    pub fn class_mask(&self) -> u16 {
        self.class_mask
    }

    /// Serializes 33 `[selector, node]` pairs in verifier-slot order.
    ///
    /// Fixed slots come first, followed by the fifteen inferred pairs. The
    /// second member of each pair adds two to its pool selector because the
    /// first selected endpoint and node remain on the main stack until the
    /// relation is checked. All numbers use minimal ScriptNum encoding.
    pub fn to_witness(&self) -> Witness {
        let mut remaining: Vec<_> = (0..CHAINS).collect();
        let mut witness = Witness::new();
        for digit in FIXED_DIGITS {
            push_opening(&mut witness, &mut remaining, self, digit, 0);
        }
        for (pair_index, &(u, v, shift)) in PAIRS.iter().enumerate() {
            let shifted = (self.class_mask >> pair_index) & 1 == 1;
            let first = if shifted { u - shift } else { u };
            let second = if shifted { v + shift } else { v };
            push_opening(&mut witness, &mut remaining, self, first, 0);
            push_opening(&mut witness, &mut remaining, self, second, 2);
        }
        debug_assert_eq!(witness.len(), 2 * OPENINGS);
        debug_assert_eq!(remaining.len(), IMPLICIT_ENDPOINTS);
        debug_assert!(remaining
            .iter()
            .all(|&index| self.digits[index] as usize == MAX_DIGIT));
        witness
    }
}

fn push_opening(
    witness: &mut Witness,
    remaining: &mut Vec<usize>,
    signature: &MixedConstantSumSignature20,
    digit: u8,
    selector_offset: usize,
) {
    let selector = remaining
        .iter()
        .position(|&index| signature.digits[index] == digit)
        .expect("signature histogram matches its class");
    let key_index = remaining.remove(selector);
    witness.push(integer(selector + selector_offset));
    witness.push(signature.nodes[key_index].as_bytes());
}

/// Wrong length, histogram, class, or a codeword outside the 160-bit prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidMixedConstantSumEncoding;
impl fmt::Display for InvalidMixedConstantSumEncoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid mixed-stage constant-sum 20-byte message encoding")
    }
}
impl std::error::Error for InvalidMixedConstantSumEncoding {}

/// Experimental fixed-parameter one-time signature for an unchanged 20-byte message.
#[derive(Debug)]
pub struct MixedConstantSumWinternitz20;

impl MixedConstantSumWinternitz20 {
    pub const MESSAGE_BYTES: usize = 20;
    pub const CHAINS: usize = CHAINS;
    pub const OPENINGS: usize = OPENINGS;
    pub const IMPLICIT_ENDPOINTS: usize = IMPLICIT_ENDPOINTS;
    pub const MAX_DIGIT: usize = MAX_DIGIT;
    pub const DIGIT_SUM: usize = 1566;
    pub const CLASS_COUNT: usize = 1 << PAIRS.len();
    pub const WITNESS_DATA_ITEMS: usize = 2 * OPENINGS;

    pub fn signing_key_from_seed(seed: [u8; 32]) -> MixedConstantSumSigningKey20 {
        MixedConstantSumSigningKey20 { seed }
    }
    pub fn generate_signing_key() -> MixedConstantSumSigningKey20 {
        let mut seed = [0; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        Self::signing_key_from_seed(seed)
    }
    pub fn public_key(key: &MixedConstantSumSigningKey20) -> MixedConstantSumPublicKey20 {
        let namespace = namespace(&key.seed);
        MixedConstantSumPublicKey20::from_commitments(core::array::from_fn(
            |index| match chain_value(chain_start(&namespace, index), MAX_DIGIT) {
                MixedChainValue::Narrow(endpoint) => endpoint,
                _ => unreachable!("the fixed chain schedule ends with RIPEMD160"),
            },
        ))
    }
    pub fn sign(
        key: MixedConstantSumSigningKey20,
        message: &[u8; 20],
    ) -> MixedConstantSumSignature20 {
        let namespace = namespace(&key.seed);
        let (digits, class_mask) = Self::encode_message(message);
        let nodes = core::array::from_fn(|index| {
            chain_value(chain_start(&namespace, index), digits[index] as usize)
        });
        MixedConstantSumSignature20 {
            nodes,
            digits,
            class_mask,
        }
    }
    pub fn encode_message(message: &[u8; 20]) -> ([u8; CHAINS], u16) {
        encoding().unrank(BigUint::from_bytes_be(message))
    }
    pub fn decode_message(digits: &[u8]) -> Result<[u8; 20], InvalidMixedConstantSumEncoding> {
        let rank = encoding().rank(digits)?;
        if rank >= (BigUint::one() << 160usize) {
            return Err(InvalidMixedConstantSumEncoding);
        }
        let bytes = rank.to_bytes_be();
        let mut message = [0; 20];
        message[20 - bytes.len()..].copy_from_slice(&bytes);
        Ok(message)
    }
    pub fn codeword_count() -> BigUint {
        encoding().capacity.clone()
    }

    /// Checks the exact entry depth, consumes the signature, and leaves no result.
    /// Caller-owned altstack state is preserved. The surrounding protocol must
    /// append its terminal predicate.
    pub fn checksig_verify_isolated_and_clear(public_key: &MixedConstantSumPublicKey20) -> Script {
        Self::verifier(public_key, false)
    }

    /// Stages 66 items first and then checks that no unrelated main-stack item
    /// remains. This saves one compiled byte while enforcing the same isolation.
    pub fn checksig_verify_staged_and_clear(public_key: &MixedConstantSumPublicKey20) -> Script {
        Self::verifier(public_key, true)
    }

    fn verifier(public_key: &MixedConstantSumPublicKey20, staged_guard: bool) -> Script {
        script! {
            if !staged_guard {
                OP_DEPTH { 2 * OPENINGS } OP_EQUALVERIFY
            }
            for _ in 0..2 * OPENINGS { OP_TOALTSTACK }
            if staged_guard {
                OP_DEPTH OP_0 OP_EQUALVERIFY
            }
            for endpoint in public_key.commitments.iter().rev() {
                { endpoint.to_vec() }
            }
            for digit in FIXED_DIGITS {
                OP_FROMALTSTACK OP_ROLL OP_FROMALTSTACK
                { mixed_suffix(MAX_DIGIT - digit as usize) }
                OP_EQUALVERIFY
            }
            for &(u, v, shift) in PAIRS.iter() {
                OP_FROMALTSTACK OP_ROLL OP_FROMALTSTACK
                { mixed_suffix(MAX_DIGIT - u as usize) }
                OP_FROMALTSTACK OP_2 OP_MAX OP_ROLL OP_FROMALTSTACK
                { mixed_suffix(MAX_DIGIT - v as usize - shift as usize) }
                OP_2DUP OP_EQUAL OP_IF OP_2SWAP OP_ENDIF
                for _ in 0..shift as usize / 2 { OP_HASH160 }
                OP_EQUALVERIFY OP_EQUALVERIFY
            }
            for _ in 0..IMPLICIT_ENDPOINTS / 2 { OP_2DROP }
        }
    }
}

fn mixed_suffix(distance: usize) -> Script {
    script! {
        if distance % 2 == 1 { OP_RIPEMD160 }
        for _ in 0..distance / 2 { OP_HASH160 }
    }
}

fn integer(value: usize) -> Vec<u8> {
    let mut bytes = [0; 8];
    let length = bitcoin::script::write_scriptint(&mut bytes, value as i64);
    bytes[..length].to_vec()
}

fn namespace(seed: &[u8; 32]) -> [u8; 20] {
    let mut engine = hash160::Hash::engine();
    engine.input(DOMAIN);
    for digit in FIXED_DIGITS {
        engine.input(&[digit]);
    }
    for &(u, v, shift) in &PAIRS {
        engine.input(&[u, v, shift]);
    }
    engine.input(seed);
    hash160::Hash::from_engine(engine).to_byte_array()
}

fn chain_start(namespace: &[u8; 20], index: usize) -> [u8; 16] {
    let mut engine = hash160::Hash::engine();
    engine.input(namespace);
    engine.input(&(index as u32).to_be_bytes());
    let digest = hash160::Hash::from_engine(engine).to_byte_array();
    digest[..16].try_into().unwrap()
}

fn chain_value(start: [u8; 16], digit: usize) -> MixedChainValue {
    let mut value = MixedChainValue::Start(start);
    for position in 0..digit {
        value = if (MAX_DIGIT - position) % 2 == 0 {
            MixedChainValue::Wide(sha256::Hash::hash(value.as_bytes()).to_byte_array())
        } else {
            MixedChainValue::Narrow(ripemd160::Hash::hash(value.as_bytes()).to_byte_array())
        };
    }
    value
}

#[derive(Clone)]
struct Class {
    counts: [u8; MAX_DIGIT + 1],
    mask: u16,
    capacity: BigUint,
    offset: BigUint,
}

struct Encoding {
    classes: Vec<Class>,
    capacity: BigUint,
}

fn encoding() -> &'static Encoding {
    static ENCODING: OnceLock<Encoding> = OnceLock::new();
    ENCODING.get_or_init(|| {
        let factorials: Vec<BigUint> = (0..=CHAINS).map(factorial).collect();
        let mut seen = HashSet::with_capacity(1 << PAIRS.len());
        let mut classes = Vec::with_capacity(1 << PAIRS.len());
        let mut total = BigUint::zero();
        for mask in 0..1u16 << PAIRS.len() {
            let counts = class_counts(mask);
            assert!(seen.insert(counts), "branch histograms must be distinct");
            let capacity = multinomial(&counts, &factorials);
            classes.push(Class {
                counts,
                mask,
                capacity: capacity.clone(),
                offset: total.clone(),
            });
            total += capacity;
        }
        assert!(total >= (BigUint::one() << 160usize));
        Encoding {
            classes,
            capacity: total,
        }
    })
}

fn class_counts(mask: u16) -> [u8; MAX_DIGIT + 1] {
    let mut counts = [0; MAX_DIGIT + 1];
    for digit in FIXED_DIGITS {
        counts[digit as usize] += 1;
    }
    counts[MAX_DIGIT] = IMPLICIT_ENDPOINTS as u8;
    for (index, &(u, v, shift)) in PAIRS.iter().enumerate() {
        if (mask >> index) & 1 == 0 {
            counts[u as usize] += 1;
            counts[v as usize] += 1;
        } else {
            counts[(u - shift) as usize] += 1;
            counts[(v + shift) as usize] += 1;
        }
    }
    debug_assert_eq!(
        counts.iter().map(|&count| count as usize).sum::<usize>(),
        CHAINS
    );
    debug_assert_eq!(
        counts
            .iter()
            .enumerate()
            .map(|(digit, &count)| digit * count as usize)
            .sum::<usize>(),
        MixedConstantSumWinternitz20::DIGIT_SUM
    );
    counts
}

fn factorial(value: usize) -> BigUint {
    (1..=value).fold(BigUint::one(), |product, factor| product * factor)
}

fn multinomial(counts: &[u8; MAX_DIGIT + 1], factorials: &[BigUint]) -> BigUint {
    let mut result = factorials[CHAINS].clone();
    for &count in counts {
        result /= &factorials[count as usize];
    }
    result
}

impl Encoding {
    fn unrank(&self, rank: BigUint) -> ([u8; CHAINS], u16) {
        let class = self
            .classes
            .iter()
            .find(|class| rank >= class.offset && rank < &class.offset + &class.capacity)
            .expect("every 160-bit message rank is inside the code");
        (
            unrank_permutation(class.counts, rank - &class.offset, &class.capacity),
            class.mask,
        )
    }

    fn rank(&self, digits: &[u8]) -> Result<BigUint, InvalidMixedConstantSumEncoding> {
        if digits.len() != CHAINS || digits.iter().any(|&digit| digit as usize > MAX_DIGIT) {
            return Err(InvalidMixedConstantSumEncoding);
        }
        let mut counts = [0; MAX_DIGIT + 1];
        for &digit in digits {
            counts[digit as usize] += 1;
        }
        let class = self
            .classes
            .iter()
            .find(|class| class.counts == counts)
            .ok_or(InvalidMixedConstantSumEncoding)?;
        Ok(&class.offset + rank_permutation(digits, class.counts, &class.capacity)?)
    }
}

fn unrank_permutation(
    mut counts: [u8; MAX_DIGIT + 1],
    mut rank: BigUint,
    capacity: &BigUint,
) -> [u8; CHAINS] {
    let mut total = capacity.clone();
    let mut remaining = CHAINS;
    core::array::from_fn(|_| {
        for digit in 0..=MAX_DIGIT {
            if counts[digit] == 0 {
                continue;
            }
            let bucket = &total * counts[digit] / remaining;
            if rank < bucket {
                total = bucket;
                counts[digit] -= 1;
                remaining -= 1;
                return digit as u8;
            }
            rank -= bucket;
        }
        unreachable!("rank lies in the remaining multiset")
    })
}

fn rank_permutation(
    digits: &[u8],
    mut counts: [u8; MAX_DIGIT + 1],
    capacity: &BigUint,
) -> Result<BigUint, InvalidMixedConstantSumEncoding> {
    let mut total = capacity.clone();
    let mut remaining = CHAINS;
    let mut rank = BigUint::zero();
    for &digit in digits {
        let digit = digit as usize;
        if counts[digit] == 0 {
            return Err(InvalidMixedConstantSumEncoding);
        }
        let prefix: usize = counts[..digit].iter().map(|&count| count as usize).sum();
        rank += &total * prefix / remaining;
        total = total * counts[digit] / remaining;
        counts[digit] -= 1;
        remaining -= 1;
    }
    Ok(rank)
}

#[cfg(test)]
mod tests;
