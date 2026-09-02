//! Winternitz signing, verification, and high-level typed APIs.

mod api;
mod fast;
pub mod signing;
pub mod utils;
pub mod verification;

pub use api::{
    CompactWots, GenericWinternitzPublicKey, WinternitzSecret, WinternitzSigningInputs, Wots,
    Wots16, Wots32, Wots4, Wots64, Wots80, LOG2_BASE,
};
pub use fast::{
    FastChainValue, FastPublicKey, FastSignature, FastSigningKey, FastWinternitz, FastWots16,
    FastWots32, FastWots4, FastWots64, FastWots80, InvalidFastPublicKeyLength,
};
pub use verification::*;
