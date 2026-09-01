/// HORS-like (Hash to Obtain Random Subset) one-time signatures in Bitcoin Script.
///
/// Based on the scheme described in the Binohash paper (Robin Linus, 2025):
/// - Setup: embed n hash commitments H(preimage_0), ..., H(preimage_{n-1}) in the locking script
/// - Signing: to sign message m, reveal preimages for a subset of t indices determined by m
/// - Verification: check that each revealed preimage hashes to the committed value at the specified index
///
/// # Witness Layout
///
/// The unlocking witness provides t (index, preimage) pairs.
/// Items are pushed in this order (first pushed = deepest on stack):
///
/// ```text
/// witness[0] = index_{t-1}     (deepest)
/// witness[1] = preimage_{t-1}
/// witness[2] = index_{t-2}
/// witness[3] = preimage_{t-2}
/// ...
/// witness[2*(t-1)] = index_0
/// witness[2*(t-1)+1] = preimage_0  (top, last pushed)
/// ```
///
/// The locking script then pushes n hashes on top of these, and verifies each
/// (index, preimage) pair against its committed hash.
use bitcoin::hashes::{hash160, Hash};
use crate::script::{script, Script};

/// Compute HASH160 of data, returning a 20-byte array.
pub fn hash160(data: &[u8]) -> [u8; 20] {
    hash160::Hash::hash(data).to_byte_array()
}

/// Generate n public key hashes from n secret preimages.
pub fn hors_public_keys(preimages: &[Vec<u8>]) -> Vec<[u8; 20]> {
    preimages.iter().map(|p| hash160(p)).collect()
}

/// Build the locking script for a HORS-like OTS.
///
/// `public_keys` is a slice of n 20-byte hash commitments H(preimage_i).
/// `t` is the number of indices/preimages revealed per signature (t <= n).
///
/// # Stack state when locking script begins (unlocking items already present)
///
/// ```text
/// top:  preimage_0              ← depth 0
///       index_0                 ← depth 1
///       preimage_1              ← depth 2
///       index_1                 ← depth 3
///       ...
///       preimage_{t-1}          ← depth 2*(t-1)
///       index_{t-1}             ← depth 2*(t-1)+1  (deepest unlocking item)
/// ```
///
/// The locking script pushes hashes on top of these, then for each of t
/// iterations picks the correct hash by index, verifies the preimage against it,
/// and cleans up. At the end all hashes are dropped and OP_TRUE is left.
pub fn hors_locking_script(public_keys: &[[u8; 20]], t: usize) -> Script {
    let n = public_keys.len();
    assert!(t <= n, "t must not exceed n");

    script! {
        // Push hashes so that hash[0] is on top (pushed last).
        // hash[n-1] is pushed first and lands deepest among hashes.
        //
        // After this block the full stack (top → bottom) is:
        //   hash[0]             ← depth 0
        //   hash[1]             ← depth 1
        //   ...
        //   hash[n-1]           ← depth n-1
        //   preimage_0          ← depth n
        //   index_0             ← depth n+1
        //   preimage_1          ← depth n+2
        //   index_1             ← depth n+3
        //   ...
        //   preimage_{t-1}      ← depth n+2*(t-1)
        //   index_{t-1}         ← depth n+2*(t-1)+1
        for pk in public_keys.iter().rev() {
            { pk.to_vec() }
        }

        // Process t (index, preimage) pairs.
        // At the start of iteration i, the i shallowest unlocking pairs have
        // been consumed (2*i items removed).  The remaining stack is:
        //
        //   hash[0]             ← depth 0
        //   hash[1]             ← depth 1
        //   ...
        //   hash[n-1]           ← depth n-1
        //   preimage_i          ← depth n      (next pair to process)
        //   index_i             ← depth n+1
        //   preimage_{i+1}      ← depth n+2
        //   index_{i+1}         ← depth n+3
        //   ...
        //
        // Steps each iteration:
        //   1. Roll index_i from depth n+1 → top
        //   2. Sanitize: clamp to [0, n-1] with OP_MIN
        //   3. OP_DUP to keep a copy (we need to OP_DROP it after EQUALVERIFY)
        //   4. Compute pick depth: after OP_DUP, stack is idx_copy(0)|idx_orig(1)|hash[0](2)|…
        //      `{1} OP_ADD` CONSUMES idx_copy and produces (idx+1) on top.
        //      After ADD: (idx+1)(0) | idx_orig(1) | hash[0](2) | … | preimage_i(n+2)
        //   5. OP_PICK(idx+1): pops (idx+1), leaving idx_orig(0)|hash[0](1)|…, then
        //      copies item at NEW depth (idx+1) after the pop = hash[idx] to top.
        //      After: hash[idx](0) | idx_orig(1) | hash[0](2) | … | preimage_i(n+2)
        //      Note: OP_PICK uses the depth AFTER popping the count, so hash[j] is at j+1
        //      in the post-pop stack (idx_orig at 0, hash[0] at 1, hash[j] at j+1).
        //      We want hash[idx] at depth idx+1 → pick value = idx+1 = (idx_copy + 1).
        //   6. Roll preimage_i from depth n+2 to top.
        //      (After PICK added one item, preimage was at n+1 before, now at n+2)
        //      After roll: preimage_i(0) | hash[idx](1) | idx_orig(2) | hash[0](3) | …
        //   7. OP_HASH160 + OP_EQUALVERIFY: consumes preimage_i and hash[idx].
        //      After: idx_orig(0) | hash[0](1) | … | hash[n-1](n) | preimage_{i+1}(n+1)
        //   8. OP_DROP idx_orig (1 drop only).
        //      After: hash[0](0) | … | hash[n-1](n-1) | preimage_{i+1}(n) | index_{i+1}(n+1)
        //      → ready for next iteration.
        for _i in 0..t {
            // Step 1: roll index_i to top (it's at depth n+1)
            { (n + 1) as u32 } OP_ROLL
            // Stack: idx_i(0) | hash[0](1) | … | hash[n-1](n) | preimage_i(n+1)

            // Step 2: sanitize index (clamp to [0, n-1])
            { (n - 1) as u32 } OP_MIN

            // Step 3: duplicate index
            OP_DUP
            // Stack: idx(0) | idx_orig(1) | hash[0](2) | … | hash[n-1](n+1) | preimage_i(n+2)

            // Step 4+5: pick hash[index] non-destructively.
            // {1} OP_ADD consumes idx_copy, leaving (idx+1) on top.
            // OP_PICK pops (idx+1), then copies from new-depth (idx+1).
            // After the pop: idx_orig(0), hash[0](1), hash[j](j+1), …
            // hash[idx] is at depth idx+1 → OP_PICK(idx+1) copies it.
            { 1u32 } OP_ADD OP_PICK
            // Stack: hash[idx](0) | idx_orig(1) | hash[0](2) | … | hash[n-1](n+1) | preimage_i(n+2)

            // Step 6: roll preimage_i to top (now at depth n+2)
            { (n + 2) as u32 } OP_ROLL
            // Stack: preimage_i(0) | hash[idx](1) | idx_orig(2) | hash[0](3) | …

            // Step 7: verify
            OP_HASH160
            OP_EQUALVERIFY
            // Stack: idx_orig(0) | hash[0](1) | … | hash[n-1](n) | preimage_{i+1}(n+1)

            // Step 8: drop the used index
            OP_DROP
            // Stack: hash[0](0) | … | hash[n-1](n-1) | preimage_{i+1}(n) | index_{i+1}(n+1)
        }

        // Drop the n remaining hash commitments.
        for _ in 0..n {
            OP_DROP
        }

        OP_TRUE
    }
}

/// Build the unlocking witness for a HORS signature.
///
/// `preimages` is the full array of n secret preimages.
/// `indices` is the sorted-or-unsorted list of t indices to reveal.
///
/// Returns a witness vector where `witness[0]` is pushed first (deepest).
pub fn hors_unlocking_witness(preimages: &[Vec<u8>], indices: &[usize]) -> Vec<Vec<u8>> {
    let t = indices.len();
    let mut witness = Vec::with_capacity(2 * t);

    // Push pairs deepest-first: pair (t-1) deepest, pair 0 shallowest/on top.
    // witness[0] = index_{t-1}, witness[1] = preimage_{t-1}, ...,
    // witness[2t-2] = index_0, witness[2t-1] = preimage_0.
    for i in (0..t).rev() {
        let idx = indices[i];
        // Encode index as minimal Bitcoin Script integer.
        witness.push(encode_script_int(idx as i64));
        witness.push(preimages[idx].clone());
    }
    witness
}

/// Encode an i64 as a minimal Bitcoin Script integer byte vector.
fn encode_script_int(v: i64) -> Vec<u8> {
    if v == 0 {
        return vec![];
    }
    let negative = v < 0;
    let mut absval = v.unsigned_abs();
    let mut result = Vec::new();
    while absval > 0 {
        result.push((absval & 0xff) as u8);
        absval >>= 8;
    }
    // Set sign bit if needed.
    if result.last().unwrap() & 0x80 != 0 {
        result.push(if negative { 0x80 } else { 0x00 });
    } else if negative {
        *result.last_mut().unwrap() |= 0x80;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{execute_script_with_inputs, execute_script};
    use crate::script::script;

    fn make_preimages(n: usize) -> Vec<Vec<u8>> {
        (0..n).map(|i| vec![i as u8; 20]).collect()
    }

    /// Sanity check: verify basic hash160 comparison works.
    #[test]
    fn test_direct_hash_verify() {
        let preimage = vec![2u8; 20];
        let expected_hash = hash160(&preimage);

        // Simple: push hash, push preimage, OP_HASH160, OP_EQUAL
        let script = script! {
            { expected_hash.to_vec() }
            { preimage.clone() }
            OP_HASH160
            OP_EQUAL
        };
        let result = execute_script(script);
        assert!(result.success, "basic hash verify failed: {:?}", result);
    }

    /// Check that execute_script_with_inputs witness ordering is as expected.
    #[test]
    fn test_witness_ordering() {
        // Witness[0] is pushed first (deepest), witness[1] is on top.
        // Script verifies: top = witness[1] = [2], and witness[0] = [1] is below.
        let witness = vec![vec![1u8], vec![2u8]];
        let script = script! {
            // Top = [2] (witness[1]), bottom = [1] (witness[0])
            // Verify top is 2
            { 2u8 } OP_EQUALVERIFY
            // Verify bottom is 1
            { 1u8 } OP_EQUAL
        };
        let result = execute_script_with_inputs(script, witness);
        assert!(result.success, "witness ordering check failed: {:?}", result);
    }

    /// Check exact stack layout as locking script starts.
    #[test]
    fn test_stack_layout_debug() {
        let n = 3usize;
        let _t = 1usize;
        let preimages = make_preimages(n);
        let public_keys = hors_public_keys(&preimages);

        // Witness: index=1 (witness[0]=deepest), preimage[1] (witness[1]=top)
        let witness = vec![
            encode_script_int(1),
            preimages[1].clone(),
        ];

        // Script: just push hashes and verify the depth of preimage.
        // After pushing n=3 hashes, preimage should be at depth 3.
        let script = script! {
            // Push 3 hashes (hash[2] deepest, hash[0] on top)
            for pk in public_keys.iter().rev() {
                { pk.to_vec() }
            }
            // Stack: hash[0](0), hash[1](1), hash[2](2), preimage[1](3), index=1(4)
            // Verify: item at depth 3 is preimage[1] by checking hash
            { 3u32 } OP_ROLL  // bring preimage[1] to top
            OP_HASH160
            { public_keys[1].to_vec() }
            OP_EQUALVERIFY  // should match
            // Drop hashes and index
            OP_DROP OP_DROP OP_DROP OP_DROP
            OP_TRUE
        };
        let result = execute_script_with_inputs(script, witness);
        assert!(result.success, "stack layout debug failed: {:?}", result);
    }

    /// Trace the locking script step by step for n=3, t=1, index=1.
    #[test]
    fn test_step_by_step_debug() {
        let n = 3usize;
        let preimages = make_preimages(n);
        let public_keys = hors_public_keys(&preimages);
        let idx = 1usize;

        let witness = vec![
            encode_script_int(idx as i64),
            preimages[idx].clone(),
        ];

        // Manually implement just step 1: roll index to top and check it's correct.
        let script_step1 = script! {
            for pk in public_keys.iter().rev() {
                { pk.to_vec() }
            }
            // Stack: hash[0](0), hash[1](1), hash[2](2), preimage[idx](3), index(4)
            // Step 1: roll index from depth n+1=4 to top
            { (n + 1) as u32 } OP_ROLL
            // Stack: index(0), hash[0](1), hash[1](2), hash[2](3), preimage[idx](4)
            { idx as u32 } OP_EQUALVERIFY  // verify index is correct
            // Now stack: hash[0](0), hash[1](1), hash[2](2), preimage[idx](3)
            OP_DROP OP_DROP OP_DROP OP_DROP
            OP_TRUE
        };
        let result = execute_script_with_inputs(script_step1, witness.clone());
        assert!(result.success, "step 1 failed: {:?}", result);

        // Step 1+2+3: roll, min, dup
        let script_step3 = script! {
            for pk in public_keys.iter().rev() {
                { pk.to_vec() }
            }
            { (n + 1) as u32 } OP_ROLL
            { (n - 1) as u32 } OP_MIN
            OP_DUP
            // Stack: idx(0), idx(1), hash[0](2), hash[1](3), hash[2](4), preimage[idx](5)
            OP_DROP  // drop the dup
            { idx as u32 } OP_EQUALVERIFY  // verify original idx
            // Stack: hash[0](0), hash[1](1), hash[2](2), preimage[idx](3)
            OP_DROP OP_DROP OP_DROP OP_DROP
            OP_TRUE
        };
        let result = execute_script_with_inputs(script_step3, witness.clone());
        assert!(result.success, "step 3 failed: {:?}", result);

        // Step 1+2+3+4+5: roll, min, dup, add, pick (using {1} OP_ADD)
        let script_step5 = script! {
            for pk in public_keys.iter().rev() {
                { pk.to_vec() }
            }
            { (n + 1) as u32 } OP_ROLL
            { (n - 1) as u32 } OP_MIN
            OP_DUP
            { 1u32 } OP_ADD OP_PICK
            // Stack: hash[idx](0), idx_orig(1), hash[0](2), hash[1](3), hash[2](4), preimage[idx](5)
            // Verify hash[idx] is at depth 0
            { public_keys[idx].to_vec() }
            OP_EQUALVERIFY
            // Drop remaining
            OP_DROP  // idx_orig
            OP_DROP OP_DROP OP_DROP OP_DROP  // hashes + preimage
            OP_TRUE
        };
        let result = execute_script_with_inputs(script_step5, witness.clone());
        assert!(result.success, "step 5 failed: {:?}", result);
    }

    #[test]
    fn test_hors_single_pair() {
        let n = 5;
        let t = 1;
        let preimages = make_preimages(n);
        let public_keys = hors_public_keys(&preimages);

        let indices = vec![2usize];
        let locking = hors_locking_script(&public_keys, t);
        let witness = hors_unlocking_witness(&preimages, &indices);

        let result = execute_script_with_inputs(locking, witness);
        assert!(result.success, "HORS single pair failed: {:?}", result);
    }

    #[test]
    fn test_hors_single_pair_index_zero() {
        let n = 5;
        let t = 1;
        let preimages = make_preimages(n);
        let public_keys = hors_public_keys(&preimages);

        let indices = vec![0usize];
        let locking = hors_locking_script(&public_keys, t);
        let witness = hors_unlocking_witness(&preimages, &indices);

        let result = execute_script_with_inputs(locking, witness);
        assert!(result.success, "HORS single pair index 0 failed: {:?}", result);
    }

    #[test]
    fn test_hors_single_pair_last_index() {
        let n = 5;
        let t = 1;
        let preimages = make_preimages(n);
        let public_keys = hors_public_keys(&preimages);

        let indices = vec![n - 1];
        let locking = hors_locking_script(&public_keys, t);
        let witness = hors_unlocking_witness(&preimages, &indices);

        let result = execute_script_with_inputs(locking, witness);
        assert!(result.success, "HORS single pair last index failed: {:?}", result);
    }

    #[test]
    fn test_hors_multiple_pairs() {
        let n = 10;
        let t = 3;
        let preimages = make_preimages(n);
        let public_keys = hors_public_keys(&preimages);

        let indices = vec![1usize, 5, 7];
        let locking = hors_locking_script(&public_keys, t);
        let witness = hors_unlocking_witness(&preimages, &indices);

        let result = execute_script_with_inputs(locking, witness);
        assert!(result.success, "HORS multiple pairs failed: {:?}", result);
    }

    #[test]
    fn test_hors_t_equals_n() {
        // Reveal all n preimages.
        let n = 4;
        let t = 4;
        let preimages = make_preimages(n);
        let public_keys = hors_public_keys(&preimages);

        let indices: Vec<usize> = (0..n).collect();
        let locking = hors_locking_script(&public_keys, t);
        let witness = hors_unlocking_witness(&preimages, &indices);

        let result = execute_script_with_inputs(locking, witness);
        assert!(result.success, "HORS t==n failed: {:?}", result);
    }

    #[test]
    fn test_hors_wrong_preimage_fails() {
        let n = 5;
        let t = 1;
        let preimages = make_preimages(n);
        let public_keys = hors_public_keys(&preimages);

        let locking = hors_locking_script(&public_keys, t);
        // Provide correct index but wrong preimage.
        let witness = vec![
            encode_script_int(2),
            b"wrong_preimage_data_here".to_vec(),
        ];
        let result = execute_script_with_inputs(locking, witness);
        assert!(!result.success, "wrong preimage should fail");
    }

    #[test]
    fn test_hors_wrong_index_with_wrong_preimage_fails() {
        let n = 5;
        let t = 1;
        let preimages = make_preimages(n);
        let public_keys = hors_public_keys(&preimages);

        let locking = hors_locking_script(&public_keys, t);
        // Provide preimage for index 0 but claim index 1.
        let witness = vec![
            encode_script_int(1),
            preimages[0].clone(), // preimage for index 0, not 1
        ];
        let result = execute_script_with_inputs(locking, witness);
        assert!(!result.success, "mismatched index/preimage should fail");
    }

    #[test]
    fn test_hors_large() {
        let n = 32;
        let t = 8;
        let preimages = make_preimages(n);
        let public_keys = hors_public_keys(&preimages);

        let indices = vec![0usize, 4, 9, 13, 17, 21, 25, 31];
        let locking = hors_locking_script(&public_keys, t);
        let witness = hors_unlocking_witness(&preimages, &indices);

        let result = execute_script_with_inputs(locking, witness);
        assert!(result.success, "HORS large failed: {:?}", result);
    }
}
