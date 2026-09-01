//! Residue-number arithmetic backed by Bitcoin Script lookup tables.
//!
//! The moduli `[4, 9, 25, 7, 11]` are pairwise coprime and have product
//! 69,300.  A value is represented by one residue for each modulus, so
//! arithmetic is performed modulo 69,300.
//!
//! Addition and subtraction first combine corresponding residues and reduce
//! the result through 107-entry lookup tables. Multiplication uses flattened
//! `m * m` tables and a lookup-row encoding for its left operand. All three
//! operations process the five moduli in 35 Script instructions.

use crate::script::*;

/// Pairwise-coprime moduli used by the residue number system.
pub const RNS_MODULI: [u32; 5] = [4, 9, 25, 7, 11];

/// Number of residues in an encoded value.
pub const RNS_RESIDUE_COUNT: u32 = RNS_MODULI.len() as u32;

/// Product of all [`RNS_MODULI`].
pub const RNS_MODULUS: u32 = 69_300;

/// Number of stack items occupied by the five addition tables.
pub const RNS_ADD_TABLE_SIZE: u32 = 107;

/// Number of stack items occupied by the five subtraction tables.
pub const RNS_SUB_TABLE_SIZE: u32 = 107;

/// Number of stack items occupied by the five multiplication tables.
pub const RNS_MUL_TABLE_SIZE: u32 = 892;

const RNS_REDUCTION_TABLE_OFFSETS: [u32; 5] = [0, 7, 24, 73, 86];
const RNS_MUL_TABLE_OFFSETS: [u32; 5] = [0, 16, 97, 722, 771];

/// Return the ordinary RNS encoding of `value` in [`RNS_MODULI`] order.
pub fn rns_encode(value: u32) -> [u32; RNS_MODULI.len()] {
    RNS_MODULI.map(|modulus| value % modulus)
}

/// Return the lookup-row encoding of `value` in [`RNS_MODULI`] order.
///
/// Coordinate `i` is `(value mod m_i) * m_i`, ready to be added to an
/// ordinary right-hand residue to address a flattened `m_i * m_i` table.
pub fn rns_encode_indexed(value: u32) -> [u32; RNS_MODULI.len()] {
    RNS_MODULI.map(|modulus| (value % modulus) * modulus)
}

/// Push an ordinary RNS value.
///
/// The residue modulo 4 is on top and the residue modulo 11 is deepest.
pub fn rns_push_value(value: u32) -> Script {
    let residues = rns_encode(value);
    script! {
        for residue in residues.iter().rev() {
            { *residue }
        }
    }
}

/// Push a left-hand RNS value encoded as multiplication-table row offsets.
///
/// The row offset for modulus 4 is on top and the offset for modulus 11 is
/// deepest. This deliberately differs from [`rns_push_value`] and is required
/// only for the left operand of [`rns_mul`]. Addition and subtraction accept
/// ordinary RNS encodings for both operands.
pub fn rns_push_indexed_value(value: u32) -> Script {
    let residues = rns_encode_indexed(value);
    script! {
        for residue in residues.iter().rev() {
            { *residue }
        }
    }
}

fn rns_push_reduction_tables(table_entry: impl Fn(u32, u32) -> u32) -> Script {
    let mut entries = Vec::with_capacity(RNS_ADD_TABLE_SIZE as usize);

    // Push the deepest table first and every table in reverse index order so
    // table entry zero ends up nearest the top of the stack.
    for &modulus in RNS_MODULI.iter().rev() {
        for index in (0..=(2 * modulus - 2)).rev() {
            entries.push(table_entry(index, modulus));
        }
    }

    debug_assert_eq!(entries.len(), RNS_ADD_TABLE_SIZE as usize);
    script! {
        for entry in entries {
            { entry }
        }
    }
}

/// Push all five flattened modular addition tables.
///
/// The table for modulus 4 is nearest the top of the stack, followed by the
/// tables for 9, 25, 7, and 11. Each table has `2m - 1` entries and maps
/// `lhs + rhs` to `(lhs + rhs) mod m`.
pub fn rns_push_add_tables() -> Script {
    rns_push_reduction_tables(|sum, modulus| sum % modulus)
}

/// Push all five flattened modular subtraction tables.
///
/// Each table has `2m - 1` entries. Index `rhs - lhs + m - 1` maps the
/// centered difference back to `(lhs - rhs) mod m`.
pub fn rns_push_sub_tables() -> Script {
    rns_push_reduction_tables(|index, modulus| {
        let difference = index as i32 - (modulus as i32 - 1);
        (-difference).rem_euclid(modulus as i32) as u32
    })
}

/// Push all five flattened modular multiplication tables.
///
/// Within each table, entry `lhs * m + rhs` contains `(lhs * rhs) mod m`.
pub fn rns_push_mul_tables() -> Script {
    let mut entries = Vec::with_capacity(RNS_MUL_TABLE_SIZE as usize);

    for &modulus in RNS_MODULI.iter().rev() {
        for lhs in (0..modulus).rev() {
            for rhs in (0..modulus).rev() {
                entries.push((lhs * rhs) % modulus);
            }
        }
    }

    debug_assert_eq!(entries.len(), RNS_MUL_TABLE_SIZE as usize);
    script! {
        for entry in entries {
            { entry }
        }
    }
}

fn rns_drop_table_items(table_size: u32) -> Script {
    script! {
        for _ in 0..table_size / 2 {
            OP_2DROP
        }
        if table_size % 2 == 1 {
            OP_DROP
        }
    }
}

/// Drop the addition tables from the top of the main stack.
pub fn rns_drop_add_tables() -> Script {
    rns_drop_table_items(RNS_ADD_TABLE_SIZE)
}

/// Drop the subtraction tables from the top of the main stack.
pub fn rns_drop_sub_tables() -> Script {
    rns_drop_table_items(RNS_SUB_TABLE_SIZE)
}

/// Drop the multiplication tables from the top of the main stack.
pub fn rns_drop_mul_tables() -> Script {
    rns_drop_table_items(RNS_MUL_TABLE_SIZE)
}

fn rns_lookup_after_add(table_offsets: [u32; 5]) -> Script {
    let steps = table_offsets
        .iter()
        .enumerate()
        .map(|(i, &table_offset)| {
            let remaining_coordinates = RNS_RESIDUE_COUNT - i as u32 - 1;
            let lhs_depth = remaining_coordinates + 1;
            let table_depth = table_offset + 2 * remaining_coordinates;
            (lhs_depth, table_depth)
        })
        .collect::<Vec<_>>();

    script! {
        for (lhs_depth, table_depth) in steps {
            // Move the matching lhs coordinate above the rhs one.
            { lhs_depth }
            OP_ROLL
            OP_ADD
            { table_depth }
            OP_ADD
            OP_PICK
            OP_TOALTSTACK
        }
    }
}

/// Add two RNS values using the addition tables beneath them.
///
/// Input main-stack layout, from deepest to top:
///
/// `add_tables | lhs | rhs`
///
/// Both operands use ordinary [`rns_push_value`] encoding and have their
/// modulus-4 coordinate on top. They are consumed and the ordinary residues
/// for `lhs + rhs mod 69,300` are left on the altstack.
pub fn rns_add() -> Script {
    rns_lookup_after_add(RNS_REDUCTION_TABLE_OFFSETS)
}

/// Subtract two RNS values using the subtraction tables beneath them.
///
/// Uses the same ordinary-operand input and output layout as [`rns_add`],
/// leaving residues for `lhs - rhs mod 69,300` on the altstack.
pub fn rns_sub() -> Script {
    let steps = RNS_REDUCTION_TABLE_OFFSETS
        .iter()
        .enumerate()
        .map(|(i, &table_offset)| {
            let modulus = RNS_MODULI[i];
            let remaining_coordinates = RNS_RESIDUE_COUNT - i as u32 - 1;
            let lhs_depth = remaining_coordinates + 1;
            // OP_SUB produces rhs - lhs. Shift its centered range by m - 1
            // while also skipping unconsumed coordinates and earlier tables.
            let table_depth = table_offset + 2 * remaining_coordinates + modulus - 1;
            (lhs_depth, table_depth)
        })
        .collect::<Vec<_>>();

    script! {
        for (lhs_depth, table_depth) in steps {
            { lhs_depth }
            OP_ROLL
            OP_SUB
            { table_depth }
            OP_ADD
            OP_PICK
            OP_TOALTSTACK
        }
    }
}

/// Multiply two RNS values using the multiplication tables beneath them.
///
/// Input layout is `mul_tables | indexed_lhs | rhs`. The left operand must use
/// [`rns_push_indexed_value`] encoding; the right operand is ordinary. The
/// result residues for `lhs * rhs mod 69,300` are left on the altstack.
pub fn rns_mul() -> Script {
    rns_lookup_after_add(RNS_MUL_TABLE_OFFSETS)
}

/// Move one ordinary RNS value from the altstack to the main stack.
pub fn rns_fromaltstack() -> Script {
    script! {
        for _ in 0..RNS_RESIDUE_COUNT {
            OP_FROMALTSTACK
        }
    }
}

/// Move the ordinary RNS value on top of the main stack to the altstack.
pub fn rns_toaltstack() -> Script {
    script! {
        for _ in 0..RNS_RESIDUE_COUNT {
            OP_TOALTSTACK
        }
    }
}

/// Consume and equality-check the top two ordinary RNS values.
pub fn rns_equalverify() -> Script {
    script! {
        for i in 0..RNS_RESIDUE_COUNT {
            { RNS_RESIDUE_COUNT - i }
            OP_ROLL
            OP_EQUALVERIFY
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, Rng, SeedableRng};

    fn run_binary(
        lhs: Script,
        rhs: u32,
        expected: u32,
        tables: Script,
        operation: Script,
        drop_tables: Script,
    ) {
        let script = script! {
            { tables }
            { lhs }
            { rns_push_value(rhs) }
            { operation }
            { drop_tables }
            { rns_push_value(expected) }
            { rns_fromaltstack() }
            { rns_equalverify() }
            OP_TRUE
        };
        crate::run(script);
    }

    fn run_add(lhs: u32, rhs: u32) {
        let expected = ((lhs as u64 + rhs as u64) % RNS_MODULUS as u64) as u32;
        run_binary(
            rns_push_value(lhs),
            rhs,
            expected,
            rns_push_add_tables(),
            rns_add(),
            rns_drop_add_tables(),
        );
    }

    fn run_sub(lhs: u32, rhs: u32) {
        let modulus = RNS_MODULUS as u64;
        let expected = ((lhs as u64 % modulus + modulus - rhs as u64 % modulus) % modulus) as u32;
        run_binary(
            rns_push_value(lhs),
            rhs,
            expected,
            rns_push_sub_tables(),
            rns_sub(),
            rns_drop_sub_tables(),
        );
    }

    fn run_mul(lhs: u32, rhs: u32) {
        let expected = ((lhs as u64 * rhs as u64) % RNS_MODULUS as u64) as u32;
        run_binary(
            rns_push_indexed_value(lhs),
            rhs,
            expected,
            rns_push_mul_tables(),
            rns_mul(),
            rns_drop_mul_tables(),
        );
    }

    #[test]
    fn test_rns_parameters_match_design() {
        assert_eq!(RNS_MODULI.iter().product::<u32>(), RNS_MODULUS);
        assert_eq!(
            RNS_MODULI
                .iter()
                .map(|modulus| 2 * modulus - 1)
                .sum::<u32>(),
            RNS_ADD_TABLE_SIZE
        );
        assert_eq!(RNS_ADD_TABLE_SIZE, RNS_SUB_TABLE_SIZE);
        assert_eq!(
            RNS_MODULI
                .iter()
                .map(|modulus| modulus * modulus)
                .sum::<u32>(),
            RNS_MUL_TABLE_SIZE
        );
        assert_eq!(
            rns_push_add_tables().compile().instructions().count(),
            RNS_ADD_TABLE_SIZE as usize
        );
        assert_eq!(
            rns_push_sub_tables().compile().instructions().count(),
            RNS_SUB_TABLE_SIZE as usize
        );
        assert_eq!(
            rns_push_mul_tables().compile().instructions().count(),
            RNS_MUL_TABLE_SIZE as usize
        );
        for operation in [rns_add(), rns_sub(), rns_mul()] {
            assert_eq!(operation.compile().instructions().count(), 35);
        }
    }

    #[test]
    fn test_rns_encodings() {
        assert_eq!(rns_encode(12345), [1, 6, 20, 4, 3]);
        assert_eq!(rns_encode_indexed(12345), [4, 54, 500, 28, 33]);
    }

    #[test]
    fn test_rns_binary_ops_boundaries() {
        for (lhs, rhs) in [
            (0, 0),
            (0, RNS_MODULUS - 1),
            (1, RNS_MODULUS - 1),
            (2, 3),
            (255, 257),
            (u16::MAX as u32, u16::MAX as u32),
            (RNS_MODULUS - 2, RNS_MODULUS - 1),
        ] {
            run_add(lhs, rhs);
            run_sub(lhs, rhs);
            run_mul(lhs, rhs);
        }
    }

    #[test]
    fn test_rns_binary_ops_exhaustive_table_coordinates() {
        // These inputs cover every sum and centered difference in the largest
        // reduction tables, plus every coordinate in the 25 x 25 mul table.
        for lhs in 0..25 {
            for rhs in 0..25 {
                run_add(lhs, rhs);
                run_sub(lhs, rhs);
                run_mul(lhs, rhs);
            }
        }
    }

    #[test]
    fn test_rns_binary_ops_random() {
        let mut rng = StdRng::seed_from_u64(0x52534e);
        for _ in 0..100 {
            let lhs = rng.gen_range(0..RNS_MODULUS);
            let rhs = rng.gen_range(0..RNS_MODULUS);
            run_add(lhs, rhs);
            run_sub(lhs, rhs);
            run_mul(lhs, rhs);
        }
    }

    fn binary_op_max_stack_items(
        tables: Script,
        lhs: Script,
        operation: Script,
        drop_tables: Script,
    ) -> usize {
        let script = script! {
            { tables }
            { lhs }
            { rns_push_value(RNS_MODULUS - 1) }
            { operation }
            { drop_tables }
            { rns_fromaltstack() }
            OP_2DROP
            OP_2DROP
            OP_DROP
            OP_TRUE
        };
        let result = crate::execute_script(script);
        assert!(result.success);
        result.stats.max_nb_stack_items
    }

    #[test]
    fn test_rns_binary_ops_respect_stack_limit() {
        assert_eq!(
            binary_op_max_stack_items(
                rns_push_add_tables(),
                rns_push_value(RNS_MODULUS - 1),
                rns_add(),
                rns_drop_add_tables(),
            ),
            118
        );
        assert_eq!(
            binary_op_max_stack_items(
                rns_push_sub_tables(),
                rns_push_value(RNS_MODULUS - 1),
                rns_sub(),
                rns_drop_sub_tables(),
            ),
            118
        );
        assert_eq!(
            binary_op_max_stack_items(
                rns_push_mul_tables(),
                rns_push_indexed_value(RNS_MODULUS - 1),
                rns_mul(),
                rns_drop_mul_tables(),
            ),
            903
        );
    }
}
