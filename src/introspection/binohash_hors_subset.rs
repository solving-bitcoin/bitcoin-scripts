//! Local 2-of-3 subset-selection consumer for exact HORS indices.
//!
//! This is a toy Script composition. It does not execute legacy ECDSA,
//! FindAndDelete, or the Binohash two-round protocol.

use crate::{
    signatures::hors::hors_exact_index_locking_script,
    support::script::{script, Script},
};

/// Authenticate one ascending pair of indices, then use it for 2-of-3 selection.
///
/// The four initial stack items use `hors_unlocking_witness`'s order:
/// `index_1, preimage_1, index_0, preimage_0` from bottom to top. The exact
/// HORS verifier consumes the opening. Copies of those same index items route
/// two of the three numeric pool tags `1, 2, 4` through `OP_ROLL`. The final
/// predicate checks their sum against the unique pair-index sum mapping.
/// There is no independent witness selector that could diverge from HORS.
pub fn authenticated_two_of_three_subset_script(public_keys: &[[u8; 20]; 3]) -> Script {
    let hors = hors_exact_index_locking_script(public_keys, 2);
    script! {
        // Copy index_0 and index_1 to altstack without changing the opening.
        { 1u32 } OP_PICK OP_TOALTSTACK
        { 3u32 } OP_PICK OP_TOALTSTACK
        { hors }
        OP_DROP // HORS leaves true; its four opening items were consumed.

        OP_FROMALTSTACK OP_FROMALTSTACK OP_SWAP // index_1, index_0
        OP_2DUP OP_ADD OP_TOALTSTACK // preserve pair sum for terminal check

        // Pool top-to-bottom is tag_0=1, tag_1=2, tag_2=4.
        OP_4 OP_2 OP_1
        OP_3 OP_ROLL // move index_1 above the three tags
        OP_ROLL OP_TOALTSTACK // select and save tag_1
        OP_2 OP_ROLL // move index_0 above the two remaining tags
        OP_ROLL // select tag_0
        OP_FROMALTSTACK OP_ADD // selected tag sum
        OP_SWAP OP_DROP // discard the unused pool tag
        OP_FROMALTSTACK // restore pair-index sum

        // Ordered 2-of-3 pairs have sums 1,2,3 and tag sums 3,5,6.
        OP_DUP OP_1 OP_EQUAL
        OP_IF
            OP_DROP OP_3
        OP_ELSE
            OP_DUP OP_2 OP_EQUAL
            OP_IF
                OP_DROP OP_5
            OP_ELSE
                OP_3 OP_EQUALVERIFY OP_6
            OP_ENDIF
        OP_ENDIF
        OP_EQUAL
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        signatures::hors::{hors_public_keys, hors_unlocking_witness},
        support::{
            execution::{execute_script_buf_with_options, execute_script_with_inputs_strict},
            script::ScriptCompilation,
        },
    };
    use bitcoin_scriptexec::Options;

    fn fixture() -> ([Vec<u8>; 3], Script) {
        let preimages = [vec![0x11; 16], vec![0x22; 16], vec![0x33; 16]];
        let public_keys: [[u8; 20]; 3] = hors_public_keys(&preimages).try_into().unwrap();
        let script = authenticated_two_of_three_subset_script(&public_keys);
        (preimages, script)
    }

    #[test]
    fn all_three_pairs_use_the_same_authenticated_indices_for_selection() {
        let (preimages, script) = fixture();
        for pair in [[0, 1], [0, 2], [1, 2]] {
            let witness = hors_unlocking_witness(&preimages, &pair);
            let result = execute_script_with_inputs_strict(script.clone(), witness);
            assert!(result.success, "pair {pair:?} failed: {result}");
            assert!(result.stack_limit_enforced);
            assert_eq!(result.final_stack.len(), 1);
            assert_eq!(result.final_stack.get(0), vec![1]);
        }
    }

    #[test]
    fn hostile_indices_and_openings_cannot_alias_a_selected_pair() {
        let (preimages, script) = fixture();
        let valid = hors_unlocking_witness(&preimages, &[0, 2]);

        let mut wrong_preimage = valid.clone();
        wrong_preimage[1] = preimages[1].clone();
        assert!(!execute_script_with_inputs_strict(script.clone(), wrong_preimage).success);

        let mut out_of_range = valid.clone();
        out_of_range[0] = vec![3];
        assert!(!execute_script_with_inputs_strict(script.clone(), out_of_range).success);

        for pair in [[1, 1], [2, 0]] {
            let witness = hors_unlocking_witness(&preimages, &pair);
            assert!(!execute_script_with_inputs_strict(script.clone(), witness).success);
        }

        for raw_index in [vec![0], vec![0x80], vec![0, 0], vec![0x81]] {
            let mut witness = valid.clone();
            witness[2] = raw_index;
            let relaxed = execute_script_buf_with_options(
                script.clone().compile_with_policy(),
                witness,
                Options {
                    require_minimal: false,
                    enforce_stack_limit: true,
                    ..Options::default()
                },
            )
            .unwrap();
            assert!(!relaxed.success, "raw index alias passed: {relaxed}");
            assert!(relaxed.stack_limit_enforced);
        }

        let mut second_alias = valid.clone();
        second_alias[0] = vec![2, 0];
        let relaxed = execute_script_buf_with_options(
            script.clone().compile_with_policy(),
            second_alias,
            Options {
                require_minimal: false,
                enforce_stack_limit: true,
                ..Options::default()
            },
        )
        .unwrap();
        assert!(!relaxed.success, "second index alias passed: {relaxed}");

        let mut excess = vec![vec![0x55]];
        excess.extend(valid);
        assert!(!execute_script_with_inputs_strict(script, excess).success);
    }
}
