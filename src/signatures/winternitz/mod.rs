//! Winternitz constructions: direct base-16, fixed-sum/composition encodings, and the original API.
pub mod base16;
pub mod constant_composition;
pub mod constant_sum;
pub mod constant_sum_mixed;
pub mod legacy;
pub mod shared;

pub use base16::{
    FastChainValue, FastCommitment, FastPublicKey, FastSignature, FastSigningKey, FastWinternitz,
    FastWots16, FastWots32, FastWots4, FastWots64, FastWots80, InvalidFastPublicKeyLength,
};
pub use constant_composition::{
    ConstantCompositionPublicKey20, ConstantCompositionSignature20,
    ConstantCompositionSigningKey20, ConstantCompositionWinternitz20,
    InvalidConstantCompositionEncoding,
};
pub use constant_sum::{
    ConstantSumPublicKey20, ConstantSumSignature20, ConstantSumSigningKey20,
    ConstantSumWinternitz20, InvalidConstantSumEncoding,
};
pub use constant_sum_mixed::{
    InvalidMixedConstantSumEncoding, MixedChainValue, MixedConstantSumPublicKey20,
    MixedConstantSumSignature20, MixedConstantSumSigningKey20, MixedConstantSumWinternitz20,
};
pub use legacy::verification::*;
pub use legacy::{
    CompactWots, GenericWinternitzPublicKey, WinternitzSecret, WinternitzSigningInputs, Wots,
    Wots16, Wots32, Wots4, Wots64, Wots80, LOG2_BASE,
};
pub use shared::{
    ChainHash, FullWidth, Hash160, Preimage16, PreimageSize, Sha256, Sha256Hash160, ShortChainValue,
};
