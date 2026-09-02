//! A strict, low-allocation base-16 Winternitz implementation.
//!
//! This module deliberately does not share the legacy verifier/converter
//! machinery. Its fixed witness layout lets the generated Script validate the
//! chain value before touching the digit and saves one stack swap per chain.

use crate::support::script::{script, Script};
use bitcoin::{
    hashes::{hash160, Hash, HashEngine},
    Witness,
};
use core::fmt;
use rand::RngCore;

/// Bytes in a HASH160 chain value.
pub const HASH_BYTES: usize = 20;
/// Winternitz base.
pub const BASE: u8 = 16;
/// Maximum base-16 digit.
pub const MAX_DIGIT: u8 = BASE - 1;

/// One HASH160 chain node or endpoint.
pub type FastChainValue = [u8; HASH_BYTES];

const CHAIN_START_DOMAIN: &[u8] = b"bitcoin-lab/winternitz-hash160/v1";

/// A one-time signing key bound to a fixed message length.
///
/// The type intentionally implements neither `Copy` nor `Clone`, and signing
/// consumes it. This prevents accidental reuse through the ordinary API. It
/// cannot prevent restoring the same seed twice, so applications must still
/// maintain durable one-time-key state.
pub struct FastSigningKey<const MESSAGE_BYTES: usize> {
    seed: [u8; 32],
}

impl<const MESSAGE_BYTES: usize> FastSigningKey<MESSAGE_BYTES> {
    /// Restores a signing key from a deterministic 32-byte seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        FastWinternitz::<MESSAGE_BYTES>::assert_parameters();
        Self { seed }
    }

    /// Generates a signing key with the operating system RNG.
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        Self::from_seed(seed)
    }

    /// Borrows the secret seed.
    ///
    /// Exposing this is necessary for durable key storage. Persist it as
    /// sensitive material and never restore it after a successful signature.
    pub fn expose_seed(&self) -> &[u8; 32] {
        &self.seed
    }
}

impl<const MESSAGE_BYTES: usize> fmt::Debug for FastSigningKey<MESSAGE_BYTES> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FastSigningKey")
            .field("message_bytes", &MESSAGE_BYTES)
            .field("seed", &"<redacted>")
            .finish()
    }
}

/// Chain endpoints committed by a Fast Winternitz verifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FastPublicKey<const MESSAGE_BYTES: usize> {
    chain_ends: Box<[FastChainValue]>,
}

impl<const MESSAGE_BYTES: usize> FastPublicKey<MESSAGE_BYTES> {
    /// Reconstructs a public key from persisted chain endpoints.
    pub fn from_chain_ends(
        chain_ends: Vec<FastChainValue>,
    ) -> Result<Self, InvalidFastPublicKeyLength> {
        FastWinternitz::<MESSAGE_BYTES>::assert_parameters();
        if chain_ends.len() != FastWinternitz::<MESSAGE_BYTES>::TOTAL_DIGITS {
            return Err(InvalidFastPublicKeyLength {
                expected: FastWinternitz::<MESSAGE_BYTES>::TOTAL_DIGITS,
                actual: chain_ends.len(),
            });
        }
        Ok(Self {
            chain_ends: chain_ends.into_boxed_slice(),
        })
    }

    /// Returns the chain endpoints in message/checksum digit order.
    pub fn chain_ends(&self) -> &[FastChainValue] {
        &self.chain_ends
    }
}

/// Public-key endpoint count did not match the message-length parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidFastPublicKeyLength {
    /// Required number of endpoints.
    pub expected: usize,
    /// Supplied number of endpoints.
    pub actual: usize,
}

impl fmt::Display for InvalidFastPublicKeyLength {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "wrong Fast Winternitz public-key length: expected {}, got {}",
            self.expected, self.actual
        )
    }
}

impl std::error::Error for InvalidFastPublicKeyLength {}

/// A Fast Winternitz signature before Bitcoin witness serialization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FastSignature<const MESSAGE_BYTES: usize> {
    chain_values: Box<[FastChainValue]>,
    digits: Box<[u8]>,
}

impl<const MESSAGE_BYTES: usize> FastSignature<MESSAGE_BYTES> {
    /// Returns the authenticated message digits followed by checksum digits.
    ///
    /// Message bytes use high-nibble/low-nibble order. Checksum digits use
    /// little-endian base-16 order so the terminal verifier can decode them
    /// with a forward Horner pass while consuming the witness backwards.
    pub fn digits(&self) -> &[u8] {
        &self.digits
    }

    /// Returns the selected HASH160 chain values.
    pub fn chain_values(&self) -> &[FastChainValue] {
        &self.chain_values
    }

    /// Serializes as `[digit_0, chain_0, digit_1, chain_1, ...]`.
    ///
    /// The chain value is therefore on top when Script consumes each pair in
    /// reverse order. Digits use canonical ScriptNum witness encodings.
    pub fn to_witness(&self) -> Witness {
        debug_assert_eq!(self.chain_values.len(), self.digits.len());
        let mut witness = Witness::new();
        for (&digit, chain_value) in self.digits.iter().zip(self.chain_values.iter()) {
            if digit == 0 {
                witness.push([]);
            } else {
                witness.push([digit]);
            }
            witness.push(chain_value);
        }
        witness
    }

    /// Serializes for the locking-size-optimized verifier.
    ///
    /// Message pairs are `[chain_0, digit_0, ..., chain_n, digit_n]`.
    /// Checksum pairs follow in reverse chain-index order. This makes Script
    /// consume checksum digits least-significant first, then message digits in
    /// reverse order, while the authenticated digits ultimately reach the
    /// checksum routine in its cheapest Horner order.
    pub fn to_size_optimized_witness(&self) -> Witness {
        debug_assert_eq!(self.chain_values.len(), self.digits.len());
        let mut witness = Witness::new();
        for index in 0..FastWinternitz::<MESSAGE_BYTES>::MESSAGE_DIGITS {
            witness.push(self.chain_values[index]);
            push_digit(&mut witness, self.digits[index]);
        }
        for checksum_index in (0..FastWinternitz::<MESSAGE_BYTES>::CHECKSUM_DIGITS).rev() {
            let index = FastWinternitz::<MESSAGE_BYTES>::MESSAGE_DIGITS + checksum_index;
            witness.push(self.chain_values[index]);
            push_digit(&mut witness, self.digits[index]);
        }
        witness
    }

    /// Serializes for the bitwise terminal verifier.
    ///
    /// Each chain contributes the four canonical bits of `15 - digit` and the
    /// selected chain node. From bottom to top a chunk is
    /// `[bit_8, bit_4, bit_2, chain, bit_1]`, so Script can consume each bit
    /// with `MINIMALIF` while keeping the chain node on top for hashing.
    pub fn to_bitwise_size_optimized_witness(&self) -> Witness {
        debug_assert_eq!(self.chain_values.len(), self.digits.len());
        let mut witness = Witness::new();
        for (&digit, chain_value) in self.digits.iter().zip(self.chain_values.iter()) {
            let remaining = MAX_DIGIT - digit;
            push_digit(&mut witness, (remaining >> 3) & 1);
            push_digit(&mut witness, (remaining >> 2) & 1);
            push_digit(&mut witness, (remaining >> 1) & 1);
            witness.push(chain_value);
            push_digit(&mut witness, remaining & 1);
        }
        witness
    }
}

/// Fixed-message-length, base-16, HASH160 Winternitz operations.
pub struct FastWinternitz<const MESSAGE_BYTES: usize>;

/// Fast Winternitz over a 4-byte message.
pub type FastWots4 = FastWinternitz<4>;
/// Fast Winternitz over a 16-byte message.
pub type FastWots16 = FastWinternitz<16>;
/// Fast Winternitz over a 32-byte message.
pub type FastWots32 = FastWinternitz<32>;
/// Fast Winternitz over a 64-byte message.
pub type FastWots64 = FastWinternitz<64>;
/// Fast Winternitz over an 80-byte message.
pub type FastWots80 = FastWinternitz<80>;

impl<const MESSAGE_BYTES: usize> FastWinternitz<MESSAGE_BYTES> {
    /// Number of base-16 message digits.
    pub const MESSAGE_DIGITS: usize = MESSAGE_BYTES * 2;
    /// Number of base-16 checksum digits.
    pub const CHECKSUM_DIGITS: usize =
        base16_digits(Self::MESSAGE_DIGITS.saturating_mul(MAX_DIGIT as usize));
    /// Total number of HASH160 chains.
    pub const TOTAL_DIGITS: usize = Self::MESSAGE_DIGITS + Self::CHECKSUM_DIGITS;

    const fn assert_parameters() {
        assert!(MESSAGE_BYTES > 0, "message length must be nonzero");
        assert!(
            Self::TOTAL_DIGITS <= u32::MAX as usize,
            "too many Winternitz chains"
        );
    }

    /// Generates a fresh one-time signing key.
    pub fn generate_signing_key() -> FastSigningKey<MESSAGE_BYTES> {
        FastSigningKey::generate()
    }

    /// Restores a deterministic one-time signing key.
    pub fn signing_key_from_seed(seed: [u8; 32]) -> FastSigningKey<MESSAGE_BYTES> {
        FastSigningKey::from_seed(seed)
    }

    /// Derives all public chain endpoints.
    ///
    /// The hot loop uses fixed-size values and performs no per-chain heap
    /// allocation, cloning, or sorting.
    pub fn public_key(key: &FastSigningKey<MESSAGE_BYTES>) -> FastPublicKey<MESSAGE_BYTES> {
        Self::assert_parameters();
        let namespace = derive_chain_namespace::<MESSAGE_BYTES>(&key.seed);
        let chain_ends = (0..Self::TOTAL_DIGITS)
            .map(|chain_index| {
                let start = derive_chain_start(&namespace, chain_index as u32);
                hash_chain(start, MAX_DIGIT)
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        FastPublicKey { chain_ends }
    }

    /// Signs one fixed-size message and consumes the one-time signing key.
    pub fn sign(
        key: FastSigningKey<MESSAGE_BYTES>,
        message: &[u8; MESSAGE_BYTES],
    ) -> FastSignature<MESSAGE_BYTES> {
        Self::assert_parameters();
        let digits = message_and_checksum_digits(message);
        debug_assert_eq!(digits.len(), Self::TOTAL_DIGITS);
        let namespace = derive_chain_namespace::<MESSAGE_BYTES>(&key.seed);
        let chain_values = digits
            .iter()
            .enumerate()
            .map(|(chain_index, &digit)| {
                let start = derive_chain_start(&namespace, chain_index as u32);
                hash_chain(start, digit)
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        FastSignature {
            chain_values,
            digits: digits.into_boxed_slice(),
        }
    }

    /// Builds the speed-optimized verifier and leaves authenticated message
    /// nibbles on the main stack in high/low order.
    ///
    /// Every chain performs exactly `15 - digit` HASH160 calls. The checksum
    /// and all chain values are consumed. The caller must consume the message
    /// and leave a terminal truthy predicate for a complete tapscript leaf.
    pub fn checksig_verify(public_key: &FastPublicKey<MESSAGE_BYTES>) -> Script {
        Self::assert_public_key(public_key);
        script! {
            for chain_index in (0..Self::TOTAL_DIGITS).rev() {
                { verify_chain_exact(public_key.chain_ends[chain_index], false) }
            }
            { recover_message_and_verify_checksum::<MESSAGE_BYTES>() }
        }
    }

    /// Builds a speed-optimized terminal verifier that consumes the entire
    /// signature and recovered message.
    ///
    /// Checksum verification is fused into the reverse chain walk. The script
    /// leaves an empty stack; append the surrounding protocol's terminal
    /// predicate (or `OP_TRUE` for an isolated complete-leaf test).
    pub fn checksig_verify_and_clear(public_key: &FastPublicKey<MESSAGE_BYTES>) -> Script {
        Self::assert_public_key(public_key);
        script! {
            // Checksum digits are stored least-significant first, so consuming
            // the witness backwards sees the most-significant digit first.
            for checksum_index in (0..Self::CHECKSUM_DIGITS).rev() {
                { verify_chain_exact(public_key.chain_ends[Self::MESSAGE_DIGITS + checksum_index], true) }
                if checksum_index == Self::CHECKSUM_DIGITS - 1 {
                    OP_TOALTSTACK
                } else {
                    OP_FROMALTSTACK
                    for _ in 0..4 {
                        OP_DUP OP_ADD
                    }
                    OP_ADD
                    OP_TOALTSTACK
                }
            }

            OP_FROMALTSTACK
            { Self::MESSAGE_DIGITS * MAX_DIGIT as usize }
            OP_SUB
            OP_TOALTSTACK

            for message_index in (0..Self::MESSAGE_DIGITS).rev() {
                { verify_chain_exact(public_key.chain_ends[message_index], true) }
                OP_FROMALTSTACK
                OP_ADD
                if message_index != 0 {
                    OP_TOALTSTACK
                }
            }
            OP_0 OP_NUMEQUALVERIFY
        }
    }

    /// Builds the script-size-oriented verifier and leaves authenticated
    /// message nibbles on the main stack.
    ///
    /// This eight-entry lookup profile has a smaller script but executes 15
    /// hashes for digits below 8 and 7 hashes otherwise. Use
    /// [`Self::checksig_verify`] when verification latency is the objective.
    pub fn checksig_verify_minimal(public_key: &FastPublicKey<MESSAGE_BYTES>) -> Script {
        Self::assert_public_key(public_key);
        script! {
            for chain_index in (0..Self::TOTAL_DIGITS).rev() {
                { verify_chain_minimal(public_key.chain_ends[chain_index], false) }
            }
            { recover_message_and_verify_checksum::<MESSAGE_BYTES>() }
        }
    }

    /// Builds the smallest strict numeric verifier and recovers the message.
    ///
    /// This profile expects [`FastSignature::to_size_optimized_witness`]. It
    /// rejects digits outside `0..=15`, uses a symmetric eight-value lookup,
    /// and leaves the authenticated message nibbles on the main stack. To save
    /// four locking bytes per chain it does not separately require the supplied
    /// chain item to be 20 bytes; the accepted relation is documented on the
    /// internal chain verifier below.
    pub fn checksig_verify_size_optimized(public_key: &FastPublicKey<MESSAGE_BYTES>) -> Script {
        Self::assert_public_key(public_key);
        script! {
            // The size witness puts checksum chain 0 on top, followed by the
            // remaining checksum chains and then message chains in reverse.
            for checksum_index in 0..Self::CHECKSUM_DIGITS {
                { verify_chain_size_optimized(public_key.chain_ends[Self::MESSAGE_DIGITS + checksum_index]) }
            }
            for message_index in (0..Self::MESSAGE_DIGITS).rev() {
                { verify_chain_size_optimized(public_key.chain_ends[message_index]) }
            }
            { recover_message_and_verify_checksum_horner::<MESSAGE_BYTES>() }
        }
    }

    /// Builds the smallest terminal verifier and consumes the message.
    ///
    /// The fragment leaves an empty stack after successful verification. The
    /// caller must append the surrounding protocol's terminal predicate.
    pub fn checksig_verify_size_optimized_and_clear(
        public_key: &FastPublicKey<MESSAGE_BYTES>,
    ) -> Script {
        Self::assert_public_key(public_key);
        script! {
            for checksum_index in 0..Self::CHECKSUM_DIGITS {
                { verify_chain_size_optimized(public_key.chain_ends[Self::MESSAGE_DIGITS + checksum_index]) }
            }
            for message_index in (0..Self::MESSAGE_DIGITS).rev() {
                { verify_chain_size_optimized(public_key.chain_ends[message_index]) }
            }
            { verify_checksum_and_clear_horner::<MESSAGE_BYTES>() }
        }
    }

    /// Builds a smaller terminal verifier using a canonical bitwise witness.
    ///
    /// The four witness bits encode `15 - digit`. Tapscript `MINIMALIF`
    /// rejects every encoding except canonical false and true, the selected
    /// bit branches perform exactly the remaining chain hashes, and the same
    /// branches accumulate the Winternitz checksum relation. The fragment
    /// leaves an empty stack; append the surrounding protocol's predicate.
    pub fn checksig_verify_bitwise_size_optimized_and_clear(
        public_key: &FastPublicKey<MESSAGE_BYTES>,
    ) -> Script {
        Self::assert_public_key(public_key);
        script! {
            OP_0 OP_TOALTSTACK
            for chain_index in (0..Self::TOTAL_DIGITS).rev() {
                if chain_index < Self::MESSAGE_DIGITS {
                    { verify_chain_bitwise_and_accumulate(public_key.chain_ends[chain_index], 1) }
                } else {
                    { verify_chain_bitwise_and_accumulate(
                        public_key.chain_ends[chain_index],
                        1usize << (4 * (chain_index - Self::MESSAGE_DIGITS)),
                    ) }
                }
            }
            OP_FROMALTSTACK
            { base16_capacity(Self::CHECKSUM_DIGITS) }
            OP_EQUALVERIFY
        }
    }

    fn assert_public_key(public_key: &FastPublicKey<MESSAGE_BYTES>) {
        Self::assert_parameters();
        assert_eq!(
            public_key.chain_ends.len(),
            Self::TOTAL_DIGITS,
            "wrong Fast Winternitz public-key length"
        );
    }
}

const fn base16_digits(mut maximum: usize) -> usize {
    let mut digits = 1;
    while maximum >= BASE as usize {
        maximum /= BASE as usize;
        digits += 1;
    }
    digits
}

const fn base16_capacity(digits: usize) -> usize {
    let mut capacity = 0;
    let mut index = 0;
    while index < digits {
        capacity = capacity * BASE as usize + MAX_DIGIT as usize;
        index += 1;
    }
    capacity
}

fn derive_chain_namespace<const MESSAGE_BYTES: usize>(seed: &[u8; 32]) -> FastChainValue {
    let mut engine = hash160::Hash::engine();
    engine.input(CHAIN_START_DOMAIN);
    engine.input(seed);
    engine.input(&(MESSAGE_BYTES as u64).to_be_bytes());
    *hash160::Hash::from_engine(engine).as_byte_array()
}

fn derive_chain_start(namespace: &FastChainValue, chain_index: u32) -> FastChainValue {
    let mut engine = hash160::Hash::engine();
    engine.input(namespace);
    engine.input(&chain_index.to_be_bytes());
    *hash160::Hash::from_engine(engine).as_byte_array()
}

fn hash_chain(mut value: FastChainValue, steps: u8) -> FastChainValue {
    for _ in 0..steps {
        value = *hash160::Hash::hash(&value).as_byte_array();
    }
    value
}

fn push_digit(witness: &mut Witness, digit: u8) {
    if digit == 0 {
        witness.push([]);
    } else {
        witness.push([digit]);
    }
}

fn message_and_checksum_digits<const MESSAGE_BYTES: usize>(
    message: &[u8; MESSAGE_BYTES],
) -> Vec<u8> {
    let mut digits = Vec::with_capacity(FastWinternitz::<MESSAGE_BYTES>::TOTAL_DIGITS);
    for &byte in message {
        digits.push(byte >> 4);
        digits.push(byte & 0x0f);
    }

    let checksum = digits
        .iter()
        .fold(0usize, |sum, &digit| sum + usize::from(MAX_DIGIT - digit));
    for index in 0..FastWinternitz::<MESSAGE_BYTES>::CHECKSUM_DIGITS {
        digits.push(((checksum >> (4 * index)) & 0x0f) as u8);
    }
    digits
}

/// Verifies one chain with the minimum possible number of executed hashes for
/// the supplied digit. Precondition: `[... digit, chain_value]`.
/// Postcondition: `[... digit]`.
fn verify_chain_exact(expected: FastChainValue, return_digit: bool) -> Script {
    script! {
        OP_SIZE { HASH_BYTES } OP_EQUALVERIFY
        OP_SWAP
        OP_DUP OP_TOALTSTACK

        // Keep [remaining_steps, chain_value]. Each conditional block hashes
        // exactly one set bit of 15 - digit, sharing all 15 hash opcodes across
        // the 16 possible paths. For an input outside 0..=15, the residual at
        // the final OP_IF is neither canonical false nor canonical true.
        // Tapscript's consensus MINIMALIF rule therefore performs the range
        // check without a separate comparison.
        { MAX_DIGIT } OP_SWAP OP_SUB OP_SWAP
        for step in [8, 4, 2] {
            OP_OVER { step } OP_GREATERTHANOREQUAL
            OP_IF
                OP_SWAP { step } OP_SUB OP_SWAP
                for _ in 0..step {
                    OP_HASH160
                }
            OP_ENDIF
        }
        OP_SWAP
        OP_IF
            OP_HASH160
        OP_ENDIF

        { expected.to_vec() }
        OP_EQUALVERIFY
        if return_digit {
            OP_FROMALTSTACK
        }
    }
}

/// Verifies one chain using a symmetric eight-entry lookup list.
fn verify_chain_minimal(expected: FastChainValue, return_digit: bool) -> Script {
    script! {
        OP_SIZE { HASH_BYTES } OP_EQUALVERIFY
        OP_SWAP
        OP_DUP OP_0 { BASE } OP_WITHIN OP_VERIFY
        OP_DUP OP_TOALTSTACK

        { 8 }
        OP_2DUP
        OP_LESSTHAN
        OP_IF
            OP_DROP
            OP_TOALTSTACK
            for _ in 0..8 {
                OP_HASH160
            }
        OP_ELSE
            OP_SUB
            OP_TOALTSTACK
        OP_ENDIF
        for _ in 0..7 {
            OP_DUP OP_HASH160
        }
        OP_FROMALTSTACK
        OP_PICK
        { expected.to_vec() }
        OP_EQUALVERIFY
        OP_2DROP OP_2DROP OP_2DROP OP_2DROP
        if return_digit {
            OP_FROMALTSTACK
        }
    }
}

/// Verifies one chain with the smallest measured strict-numeric lookup.
///
/// Precondition: `[... chain_value, digit]`. Postcondition: the digit is on
/// the altstack. Negative digits fail at `OP_PICK`; `16` and above fail the
/// explicit upper bound; oversized ScriptNums fail numeric decoding.
///
/// The fragment intentionally omits `OP_SIZE 20 OP_EQUALVERIFY`. For digit 15
/// the selected item is compared directly with the 20-byte endpoint, which
/// enforces its length. For every smaller digit, at least one HASH160 executes
/// before the comparison and normalizes the selected value to 20 bytes. The
/// signer always emits 20-byte nodes, but the verifier relation also admits an
/// arbitrary-length preimage for digits below 15. That tradeoff saves four
/// serialized locking bytes per chain and is specific to this size profile.
fn verify_chain_size_optimized(expected: FastChainValue) -> Script {
    script! {
        OP_DUP { BASE } OP_LESSTHAN OP_VERIFY
        OP_DUP OP_TOALTSTACK

        { 8 }
        OP_2DUP OP_LESSTHAN
        OP_IF
            OP_DROP OP_TOALTSTACK
            for _ in 0..8 {
                OP_HASH160
            }
        OP_ELSE
            OP_SUB OP_TOALTSTACK
        OP_ENDIF
        for _ in 0..7 {
            OP_DUP OP_HASH160
        }
        OP_FROMALTSTACK OP_PICK
        { expected.to_vec() }
        OP_EQUALVERIFY
        OP_2DROP OP_2DROP OP_2DROP OP_2DROP
    }
}

/// Verifies one chain from four canonical remaining-distance bits and adds
/// their weighted value to the accumulator on the altstack.
///
/// Precondition: `[... bit_8, bit_4, bit_2, chain_value, bit_1]` with the
/// accumulator at the bottom of the altstack. Postcondition: the five main
/// stack items are consumed and the updated accumulator remains on altstack.
fn verify_chain_bitwise_and_accumulate(expected: FastChainValue, place: usize) -> Script {
    script! {
        OP_IF
            OP_HASH160
            { add_weight_to_altstack(place) }
        OP_ENDIF

        OP_SWAP
        OP_IF
            OP_HASH160 OP_HASH160
            { add_weight_to_altstack(2 * place) }
        OP_ENDIF

        OP_SWAP
        OP_IF
            for _ in 0..4 {
                OP_HASH160
            }
            { add_weight_to_altstack(4 * place) }
        OP_ENDIF

        OP_SWAP
        OP_IF
            for _ in 0..8 {
                OP_HASH160
            }
            { add_weight_to_altstack(8 * place) }
        OP_ENDIF

        { expected.to_vec() }
        OP_EQUALVERIFY
    }
}

fn add_weight_to_altstack(weight: usize) -> Script {
    if weight == 1 {
        script! { OP_FROMALTSTACK OP_1ADD OP_TOALTSTACK }
    } else {
        script! { OP_FROMALTSTACK { weight } OP_ADD OP_TOALTSTACK }
    }
}

fn recover_message_and_verify_checksum<const MESSAGE_BYTES: usize>() -> Script {
    script! {
        // Preserve message digits while accumulating max_sum - actual_sum.
        OP_FROMALTSTACK OP_DUP OP_NEGATE
        for _ in 1..FastWinternitz::<MESSAGE_BYTES>::MESSAGE_DIGITS {
            OP_FROMALTSTACK OP_TUCK OP_SUB
        }
        { FastWinternitz::<MESSAGE_BYTES>::MESSAGE_DIGITS * MAX_DIGIT as usize }
        OP_ADD

        // Checksum digits are little-endian base 16.
        OP_FROMALTSTACK
        for checksum_index in 1..FastWinternitz::<MESSAGE_BYTES>::CHECKSUM_DIGITS {
            OP_FROMALTSTACK
            for _ in 0..(4 * checksum_index) {
                OP_DUP OP_ADD
            }
            OP_ADD
        }
        OP_EQUALVERIFY
    }
}

fn recover_message_and_verify_checksum_horner<const MESSAGE_BYTES: usize>() -> Script {
    script! {
        // Preserve message digits while accumulating max_sum - actual_sum.
        OP_FROMALTSTACK OP_DUP OP_NEGATE
        for _ in 1..FastWinternitz::<MESSAGE_BYTES>::MESSAGE_DIGITS {
            OP_FROMALTSTACK OP_TUCK OP_SUB
        }
        { FastWinternitz::<MESSAGE_BYTES>::MESSAGE_DIGITS * MAX_DIGIT as usize }
        OP_ADD

        // The custom witness order exposes checksum digits most-significant
        // first, so one fixed-width Horner pass is smallest.
        OP_FROMALTSTACK
        for _ in 1..FastWinternitz::<MESSAGE_BYTES>::CHECKSUM_DIGITS {
            for _ in 0..4 {
                OP_DUP OP_ADD
            }
            OP_FROMALTSTACK OP_ADD
        }
        OP_EQUALVERIFY
    }
}

fn verify_checksum_and_clear_horner<const MESSAGE_BYTES: usize>() -> Script {
    script! {
        OP_FROMALTSTACK
        for _ in 1..FastWinternitz::<MESSAGE_BYTES>::MESSAGE_DIGITS {
            OP_FROMALTSTACK OP_ADD
        }

        OP_FROMALTSTACK
        for _ in 1..FastWinternitz::<MESSAGE_BYTES>::CHECKSUM_DIGITS {
            for _ in 0..4 {
                OP_DUP OP_ADD
            }
            OP_FROMALTSTACK OP_ADD
        }
        OP_ADD
        { FastWinternitz::<MESSAGE_BYTES>::MESSAGE_DIGITS * MAX_DIGIT as usize }
        OP_EQUALVERIFY
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        signatures::winternitz::{
            BinarysearchVerifier, BruteforceVerifier, CompactWots, ListpickVerifier, Parameters,
            VoidConverter, Winternitz, Wots, Wots32,
        },
        support::execution::{execute_script, execute_script_with_inputs},
    };
    use bitcoin::consensus::encode::serialize;
    use bitcoin::hex::DisplayHex;

    const SEED: [u8; 32] = [0x42; 32];
    const MESSAGE: [u8; 32] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2,
        0xe1, 0xf0,
    ];

    fn fixture() -> (FastPublicKey<32>, FastSignature<32>) {
        let key = FastWots32::signing_key_from_seed(SEED);
        let public_key = FastWots32::public_key(&key);
        let signature = FastWots32::sign(key, &MESSAGE);
        (public_key, signature)
    }

    fn assert_terminal_round_trip<const MESSAGE_BYTES: usize>(message: [u8; MESSAGE_BYTES]) {
        let seed = [MESSAGE_BYTES as u8; 32];
        let key = FastWinternitz::<MESSAGE_BYTES>::signing_key_from_seed(seed);
        let public_key = FastWinternitz::<MESSAGE_BYTES>::public_key(&key);
        let signature = FastWinternitz::<MESSAGE_BYTES>::sign(key, &message);
        let result = execute_script(script! {
            { signature.to_witness() }
            { FastWinternitz::<MESSAGE_BYTES>::checksig_verify_and_clear(&public_key) }
            OP_TRUE
        });
        assert!(result.success, "length {MESSAGE_BYTES}: {result}");
        assert_eq!(result.final_stack.len(), 1);
        assert!(result.stats.max_nb_stack_items <= 1000);

        let bitwise_signature = FastWinternitz::<MESSAGE_BYTES>::sign(
            FastWinternitz::<MESSAGE_BYTES>::signing_key_from_seed(seed),
            &message,
        );
        let result = execute_script(script! {
            { bitwise_signature.to_bitwise_size_optimized_witness() }
            { FastWinternitz::<MESSAGE_BYTES>::checksig_verify_bitwise_size_optimized_and_clear(&public_key) }
            OP_TRUE
        });
        assert!(
            result.success,
            "bitwise size profile, length {MESSAGE_BYTES}: {result}"
        );
        assert_eq!(result.final_stack.len(), 1);
        assert!(result.stats.max_nb_stack_items <= 1000);

        let size_signature = FastWinternitz::<MESSAGE_BYTES>::sign(
            FastWinternitz::<MESSAGE_BYTES>::signing_key_from_seed(seed),
            &message,
        );
        let result = execute_script(script! {
            { size_signature.to_size_optimized_witness() }
            { FastWinternitz::<MESSAGE_BYTES>::checksig_verify_size_optimized_and_clear(&public_key) }
            OP_TRUE
        });
        assert!(
            result.success,
            "size profile, length {MESSAGE_BYTES}: {result}"
        );
        assert_eq!(result.final_stack.len(), 1);
        assert!(result.stats.max_nb_stack_items <= 1000);
    }

    fn assert_message_output(verifier: Script, witness: Witness) {
        let expected = MESSAGE
            .into_iter()
            .flat_map(|byte| [byte >> 4, byte & 0x0f])
            .collect::<Vec<_>>();
        let result = execute_script(script! {
            { witness }
            { verifier }
            for digit in expected.into_iter().rev() {
                { digit } OP_NUMEQUALVERIFY
            }
            OP_TRUE
        });
        assert!(result.success, "{result}");
        assert!(result.stats.max_nb_stack_items <= 1000);
    }

    #[test]
    fn parameters_match_wots16_profile() {
        assert_eq!(FastWots32::MESSAGE_DIGITS, 64);
        assert_eq!(FastWots32::CHECKSUM_DIGITS, 3);
        assert_eq!(FastWots32::TOTAL_DIGITS, 67);
    }

    #[test]
    fn supported_radix_list_sweep_selects_base16_for_script_size() {
        let secret = vec![0x42; 32];
        let measured = (4..=8)
            .map(|log2_base| {
                let parameters = Parameters::new_by_bit_length(256, log2_base);
                let public_key = super::super::generate_public_key(&parameters, &secret);
                Winternitz::<ListpickVerifier, VoidConverter>::new()
                    .checksig_verify(&parameters, &public_key)
                    .len()
            })
            .collect::<Vec<_>>();
        assert_eq!(measured, [4_908, 5_631, 7_169, 10_585, 16_916]);
        assert_eq!(measured.iter().min(), measured.first());
    }

    #[test]
    fn host_derivation_matches_independent_python_vector() {
        let (public_key, signature) = fixture();
        assert_eq!(
            public_key.chain_ends()[0].to_lower_hex_string(),
            "e7cba209d0f5143ec68a0047fdda4e56ce24a593"
        );
        assert_eq!(
            signature.chain_values()[0].to_lower_hex_string(),
            "fe39bed9c9449e7c5ee3df13b048b2e6168baef4"
        );
        assert_eq!(signature.digits()[..4], [0, 0, 1, 1]);
    }

    #[test]
    fn all_typed_lengths_and_checksum_boundaries_verify() {
        assert_terminal_round_trip([0x00; 4]);
        assert_terminal_round_trip([0xff; 4]);
        assert_terminal_round_trip([0x00; 16]);
        assert_terminal_round_trip([0xff; 16]);
        assert_terminal_round_trip([0x00; 32]);
        assert_terminal_round_trip([0xff; 32]);
        assert_terminal_round_trip([0x00; 64]);
        assert_terminal_round_trip([0xff; 64]);
        assert_terminal_round_trip([0x00; 80]);
        assert_terminal_round_trip([0xff; 80]);
    }

    #[test]
    fn public_key_round_trips_and_rejects_wrong_endpoint_count() {
        let (public_key, _) = fixture();
        let restored = FastPublicKey::<32>::from_chain_ends(public_key.chain_ends().to_vec())
            .expect("valid endpoint count");
        assert_eq!(restored, public_key);

        let error = FastPublicKey::<32>::from_chain_ends(vec![[0; HASH_BYTES]; 66])
            .expect_err("short public key must fail");
        assert_eq!(error.expected, FastWots32::TOTAL_DIGITS);
        assert_eq!(error.actual, 66);
    }

    #[test]
    fn exact_and_minimal_verifiers_recover_message() {
        let (public_key, signature) = fixture();
        let witness = signature.to_witness();
        assert_message_output(FastWots32::checksig_verify(&public_key), witness.clone());
        assert_message_output(FastWots32::checksig_verify_minimal(&public_key), witness);
        assert_message_output(
            FastWots32::checksig_verify_size_optimized(&public_key),
            signature.to_size_optimized_witness(),
        );
    }

    #[test]
    fn fused_terminal_verifier_is_clean() {
        let (public_key, signature) = fixture();
        let result = execute_script(script! {
            { signature.to_witness() }
            { FastWots32::checksig_verify_and_clear(&public_key) }
            OP_TRUE
        });
        assert!(result.success, "{result}");
        assert_eq!(result.final_stack.len(), 1);
        assert!(result.stats.max_nb_stack_items <= 1000);

        let result = execute_script(script! {
            { signature.to_size_optimized_witness() }
            { FastWots32::checksig_verify_size_optimized_and_clear(&public_key) }
            OP_TRUE
        });
        assert!(result.success, "size profile: {result}");
        assert_eq!(result.final_stack.len(), 1);
        assert!(result.stats.max_nb_stack_items <= 1000);
    }

    #[test]
    fn rejects_wrong_chain_value_and_public_key() {
        let (public_key, signature) = fixture();
        let mut bad_witness = signature.to_witness().to_vec();
        bad_witness[1][0] ^= 1;
        let result = execute_script(script! {
            { bad_witness }
            { FastWots32::checksig_verify_and_clear(&public_key) }
            OP_TRUE
        });
        assert!(!result.success);

        let mut bad_size_witness = signature.to_size_optimized_witness().to_vec();
        bad_size_witness[0][0] ^= 1;
        let result = execute_script(script! {
            { bad_size_witness }
            { FastWots32::checksig_verify_size_optimized_and_clear(&public_key) }
            OP_TRUE
        });
        assert!(!result.success);

        let mut wrong_public_key = public_key.clone();
        wrong_public_key.chain_ends[0][0] ^= 1;
        let result = execute_script(script! {
            { signature.to_witness() }
            { FastWots32::checksig_verify_and_clear(&wrong_public_key) }
            OP_TRUE
        });
        assert!(!result.success);

        let result = execute_script(script! {
            { signature.to_size_optimized_witness() }
            { FastWots32::checksig_verify_size_optimized_and_clear(&wrong_public_key) }
            OP_TRUE
        });
        assert!(!result.success);
    }

    #[test]
    fn rejects_out_of_range_and_malformed_digits() {
        let (public_key, signature) = fixture();
        for invalid in [vec![16], vec![0x81], vec![1, 0, 0, 0, 0]] {
            let mut witness = signature.to_witness().to_vec();
            witness[0] = invalid.clone();
            let result = execute_script(script! {
                { witness }
                { FastWots32::checksig_verify_and_clear(&public_key) }
                OP_TRUE
            });
            assert!(!result.success);

            let mut size_witness = signature.to_size_optimized_witness().to_vec();
            size_witness[1] = invalid;
            let result = execute_script(script! {
                { size_witness }
                { FastWots32::checksig_verify_size_optimized_and_clear(&public_key) }
                OP_TRUE
            });
            assert!(!result.success);
        }
    }

    #[test]
    fn rejects_wrong_chain_lengths_and_witness_item_counts() {
        let (public_key, signature) = fixture();
        for invalid_length in [19, 21] {
            let mut witness = signature.to_witness().to_vec();
            witness[1] = vec![0; invalid_length];
            let result = execute_script(script! {
                { witness }
                { FastWots32::checksig_verify_and_clear(&public_key) }
                OP_TRUE
            });
            assert!(!result.success);
        }

        let mut missing = signature.to_witness().to_vec();
        missing.pop();
        let result = execute_script(script! {
            { missing }
            { FastWots32::checksig_verify_and_clear(&public_key) }
            OP_TRUE
        });
        assert!(!result.success);

        let mut extra = signature.to_witness().to_vec();
        extra.insert(0, Vec::new());
        let result = execute_script(script! {
            { extra }
            { FastWots32::checksig_verify_and_clear(&public_key) }
            OP_TRUE
        });
        assert!(
            !result.success,
            "tapscript cleanstack must reject extra input"
        );

        let mut size_missing = signature.to_size_optimized_witness().to_vec();
        size_missing.pop();
        let result = execute_script(script! {
            { size_missing }
            { FastWots32::checksig_verify_size_optimized_and_clear(&public_key) }
            OP_TRUE
        });
        assert!(!result.success);

        let mut size_extra = signature.to_size_optimized_witness().to_vec();
        size_extra.insert(0, Vec::new());
        let result = execute_script(script! {
            { size_extra }
            { FastWots32::checksig_verify_size_optimized_and_clear(&public_key) }
            OP_TRUE
        });
        assert!(
            !result.success,
            "tapscript cleanstack must reject extra input"
        );
    }

    #[test]
    fn rejects_wrong_checksum_even_with_valid_chains() {
        let key = FastWots32::signing_key_from_seed(SEED);
        let public_key = FastWots32::public_key(&key);
        let mut signature = FastWots32::sign(key, &MESSAGE);
        let checksum_index = FastWots32::MESSAGE_DIGITS;
        signature.digits[checksum_index] ^= 1;
        let namespace = derive_chain_namespace::<32>(&SEED);
        signature.chain_values[checksum_index] = hash_chain(
            derive_chain_start(&namespace, checksum_index as u32),
            signature.digits[checksum_index],
        );

        let result = execute_script(script! {
            { signature.to_witness() }
            { FastWots32::checksig_verify_and_clear(&public_key) }
            OP_TRUE
        });
        assert!(!result.success);

        let result = execute_script(script! {
            { signature.to_size_optimized_witness() }
            { FastWots32::checksig_verify_size_optimized_and_clear(&public_key) }
            OP_TRUE
        });
        assert!(!result.success);
    }

    #[test]
    fn performance_profiles_are_measurably_distinct() {
        let (public_key, signature) = fixture();
        let witness = signature.to_witness();
        let exact = FastWots32::checksig_verify(&public_key);
        let minimal = FastWots32::checksig_verify_minimal(&public_key);
        let clear = FastWots32::checksig_verify_and_clear(&public_key);
        let size = FastWots32::checksig_verify_size_optimized(&public_key);
        let size_clear = FastWots32::checksig_verify_size_optimized_and_clear(&public_key);
        let size_witness = signature.to_size_optimized_witness();
        let bitwise_clear =
            FastWots32::checksig_verify_bitwise_size_optimized_and_clear(&public_key);
        let bitwise_witness = signature.to_bitwise_size_optimized_witness();
        let exact_result = execute_script_with_inputs(
            script! {
                { exact.clone() }
                for _ in 0..FastWots32::MESSAGE_DIGITS {
                    OP_DROP
                }
                OP_TRUE
            },
            witness.to_vec(),
        );
        let minimal_result = execute_script_with_inputs(
            script! {
                { minimal.clone() }
                for _ in 0..FastWots32::MESSAGE_DIGITS {
                    OP_DROP
                }
                OP_TRUE
            },
            witness.to_vec(),
        );
        let clear_result =
            execute_script_with_inputs(script! {{ clear.clone() } OP_TRUE}, witness.to_vec());
        let size_result = execute_script_with_inputs(
            script! {
                { size.clone() }
                for _ in 0..FastWots32::MESSAGE_DIGITS {
                    OP_DROP
                }
                OP_TRUE
            },
            size_witness.to_vec(),
        );
        let size_clear_result = execute_script_with_inputs(
            script! {{ size_clear.clone() } OP_TRUE},
            size_witness.to_vec(),
        );
        let bitwise_clear_result = execute_script_with_inputs(
            script! {{ bitwise_clear.clone() } OP_TRUE},
            bitwise_witness.to_vec(),
        );
        assert!(exact_result.success, "{exact_result}");
        assert!(minimal_result.success, "{minimal_result}");
        assert!(clear_result.success, "{clear_result}");
        assert!(size_result.success, "{size_result}");
        assert!(size_clear_result.success, "{size_clear_result}");
        assert!(bitwise_clear_result.success, "{bitwise_clear_result}");
        let exact_hashes = signature
            .digits()
            .iter()
            .map(|&digit| usize::from(MAX_DIGIT - digit))
            .sum::<usize>();
        let minimal_hashes = signature
            .digits()
            .iter()
            .map(|&digit| if digit < 8 { 15 } else { 7 })
            .sum::<usize>();
        assert!(exact_hashes < minimal_hashes);
        assert!(minimal.len() < exact.len());
        assert!(size.len() < minimal.len());
        assert!(size_clear.len() < size.len());
        assert!(bitwise_clear.len() < size_clear.len());

        let legacy_parameters = Parameters::new_by_bit_length(256, 4);
        let legacy_secret = vec![0x42; 20];
        let legacy_public_key =
            super::super::generate_public_key(&legacy_parameters, &legacy_secret);
        let legacy_list = Winternitz::<ListpickVerifier, VoidConverter>::new()
            .checksig_verify(&legacy_parameters, &legacy_public_key);
        let legacy_binary = Winternitz::<BinarysearchVerifier, VoidConverter>::new()
            .checksig_verify(&legacy_parameters, &legacy_public_key);
        let legacy_bruteforce = Winternitz::<BruteforceVerifier, VoidConverter>::new()
            .checksig_verify(&legacy_parameters, &legacy_public_key);
        let legacy_standard_witness = Wots32::sign_to_raw_witness(&legacy_secret, &[0; 32]);
        let legacy_compact_witness = Wots32::compact_sign_to_raw_witness(&legacy_secret, &[0; 32]);

        eprintln!(
            "fast-wots32 exact={} minimal={} clear={} size={} size_clear={} bitwise_clear={} witness={} bitwise_witness={} exact_hashes={} minimal_hashes={} exact_ops={} minimal_ops={} clear_ops={} size_ops={} size_clear_ops={} bitwise_clear_ops={} exact_stack={} minimal_stack={} clear_stack={} size_stack={} size_clear_stack={} bitwise_clear_stack={} legacy_list={} legacy_binary={} legacy_bruteforce={} legacy_witness={} legacy_compact_witness={}",
            exact.len(),
            minimal.len(),
            clear.len(),
            size.len(),
            size_clear.len(),
            bitwise_clear.len(),
            serialize(&witness).len(),
            serialize(&bitwise_witness).len(),
            exact_hashes,
            minimal_hashes,
            exact_result.stats.opcode_count,
            minimal_result.stats.opcode_count,
            clear_result.stats.opcode_count,
            size_result.stats.opcode_count,
            size_clear_result.stats.opcode_count,
            bitwise_clear_result.stats.opcode_count,
            exact_result.stats.max_nb_stack_items,
            minimal_result.stats.max_nb_stack_items,
            clear_result.stats.max_nb_stack_items,
            size_result.stats.max_nb_stack_items,
            size_clear_result.stats.max_nb_stack_items,
            bitwise_clear_result.stats.max_nb_stack_items,
            legacy_list.len(),
            legacy_binary.len(),
            legacy_bruteforce.len(),
            serialize(&legacy_standard_witness).len(),
            serialize(&legacy_compact_witness).len(),
        );
    }
}
