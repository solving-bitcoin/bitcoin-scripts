//! Canonical Adler-32 state with deferred modular reductions.
use crate::{arithmetic::u32::stack::verify_canonical_byte, support::script::*};

pub const MODULUS: u32 = 65_521;
pub const MAX_BYTES: u32 = 997;

/// Reduce a nonnegative, bounded ScriptNum without disabled DIV/MOD opcodes.
fn reduce(bound: u32) -> Script {
    let mut multiples = Vec::new();
    let mut multiple = MODULUS;
    while multiple <= bound {
        multiples.push(multiple);
        multiple *= 2;
    }
    script! {
        for multiple in multiples.into_iter().rev() {
            OP_DUP { multiple } OP_GREATERTHANOREQUAL
            OP_IF { multiple } OP_SUB OP_ENDIF
        }
    }
}

/// Consume `byte_count` canonical byte-valued ScriptNums in bottom-to-top
/// message order and return canonical residues `A B`, with A below B.
///
/// Both caller stacks are preserved. There are no hints. For positive n the
/// combined peak is n+3 plus preserved items; for n=0 it is 2 plus preserved
/// items. The caller must bind/consume both outputs and supply a terminal
/// predicate. This checksum provides error detection, not authentication.
pub fn adler32_state(byte_count: u32) -> Script {
    assert!(byte_count <= MAX_BYTES, "Adler-32 supports 0..=997 bytes");
    // A <= 1+255n and B <= n+255n(n+1)/2, safely inside signed four-byte
    // ScriptNum. Validate before allocating accumulators to avoid n+5 peak.
    script! {
        for _ in 0..byte_count {
            { verify_canonical_byte() } OP_TOALTSTACK
        }
        1 0
        for _ in 0..byte_count {
            OP_FROMALTSTACK OP_ROT OP_ADD OP_DUP OP_ROT OP_ADD
        }
        OP_SWAP { reduce(1 + 255 * byte_count) }
        OP_SWAP { reduce(byte_count + 255 * byte_count * (byte_count + 1) / 2) }
    }
}
