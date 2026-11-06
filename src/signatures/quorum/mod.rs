//! Grouped native tapscript Schnorr quorum with public signature weights.

use std::collections::BTreeSet;

use bitcoin::secp256k1::XOnlyPublicKey;

use crate::{arithmetic::scriptint::mul_by_constant, support::script::*};

pub const MAX_KEYS: usize = 995;
pub const MAX_WEIGHT: u32 = 16;

/// Consume one signature item per key and verify that the sum of the weights
/// of valid signatures is at least `threshold`. Empty signature items
/// contribute zero. All keys must be unique, each group must be nonempty,
/// and group weights must be in `1..=16`. There may be at most 995 keys.
/// The first listed key's signature is the top witness item.
/// The fragment preserves both caller stacks for an exact input suffix,
/// returns no item, and uses no hints.
pub fn verify_weighted_quorum(groups: &[(u32, &[XOnlyPublicKey])], threshold: u32) -> Script {
    let mut seen = BTreeSet::new();
    let mut total = 0;
    for &(weight, keys) in groups {
        assert!(
            (1..=MAX_WEIGHT).contains(&weight),
            "key weights must be 1..=16"
        );
        assert!(!keys.is_empty(), "weighted groups must be nonempty");
        assert!(
            keys.len() <= MAX_KEYS - seen.len(),
            "weighted quorum exceeds 995 keys"
        );
        for key in keys {
            assert!(
                seen.insert(key.serialize()),
                "weighted quorum keys must be unique"
            );
        }
        total += weight * keys.len() as u32;
    }
    assert!(
        (1..=total).contains(&threshold),
        "threshold must be attainable and positive"
    );

    script! {
        0 OP_TOALTSTACK
        for (weight, keys) in groups {
            0
            for key in keys.iter() {
                {key.serialize().to_vec()} OP_CHECKSIGADD
            }
            {mul_by_constant(*weight)}
            OP_FROMALTSTACK OP_ADD OP_TOALTSTACK
        }
        OP_FROMALTSTACK {threshold} OP_GREATERTHANOREQUAL OP_VERIFY
    }
}
