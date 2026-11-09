//! A fixed-size sparse witness for exact-threshold tapscript signatures.

use std::collections::BTreeSet;

use bitcoin::secp256k1::XOnlyPublicKey;

use crate::{arithmetic::scriptint::verify_canonical, support::script::*};

/// Verify `threshold` nonempty signatures under distinct listed keys.
///
/// Witness suffix, bottom to top:
/// `signature[k-1] depth[k-1] ... signature[0] depth[0]`.
/// Depth zero denotes the final key in `keys`, and consumed depths must
/// strictly increase. Keys must be distinct. The exact suffix is consumed,
/// both caller stacks are preserved, and a complete leaf needs a predicate.
pub fn verify_sparse_threshold(keys: &[XOnlyPublicKey], threshold: usize) -> Script {
    let n = keys.len();
    assert!(
        (1..=994).contains(&n) && (1..=n).contains(&threshold) && 2 * threshold <= 996 - n,
        "sparse threshold requires 1 <= threshold <= keys and keys + 2 * threshold <= 996"
    );
    let unique: BTreeSet<_> = keys.iter().copied().collect();
    assert_eq!(unique.len(), n, "threshold public keys must be distinct");

    script! {
        for key in keys {{key.serialize().to_vec()}}
        -1
        for _ in 0..threshold {
            {n + 1} OP_ROLL
            {verify_canonical()}
            OP_2DUP OP_LESSTHAN OP_VERIFY OP_NIP
            OP_DUP {n} OP_LESSTHAN OP_VERIFY

            // The previous depth stays above the key table. Bring up the
            // signature, then add those two items to the key's table depth.
            {n + 1} OP_ROLL
            OP_OVER 2 OP_ADD OP_PICK
            OP_CHECKSIGVERIFY
        }
        OP_DROP
        for _ in 0..n { OP_DROP }
    }
}
