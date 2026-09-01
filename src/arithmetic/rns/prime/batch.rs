//! Batched prime-RNS multiplication with per-coordinate table reuse.
//!
//! Unlike [`super::mul`], this fragment expects both inputs and produces its
//! outputs in coordinate-major order. From the top of the input stack, the
//! first `products` pairs are the modulus-2 `(lhs, rhs)` pairs in product
//! order, followed by the modulus-3 pairs, and so on. Within each pair `rhs`
//! is the top item. Results are pushed to the altstack in the same processing
//! order, so they are popped in reverse coordinate and reverse product order.
//!
//! The fragment consumes every operand, leaves no lookup table behind, and
//! does not validate input ranges. A selected coordinate installs one table,
//! queries it non-destructively for every product, then drops the full table.

use crate::{arithmetic::u31::U31_LOOKUP_STACK_LIMIT, support::script::*};

use super::{
    compact_binary_horner_coordinate_mul, drop_items, full_table_entries, projective_table_entries,
    push_table_entries, reduce_projective_sum, strategy, table_items, ternary_coordinate_mul,
    MulStrategy, MODULI, RESIDUE_COUNT,
};

/// Maximum number of coordinate-major products accepted by [`mul`].
///
/// Seven products already require 1,050 operand items before execution, above
/// Bitcoin Script's combined 1,000-item main/altstack limit.
pub const MAX_PRODUCTS: u32 = 6;

/// Exact serialized-byte categories for one generated batch fragment.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CostBreakdown {
    /// Literal bytes that install the selected coordinate tables.
    pub table_push: usize,
    /// Bytes that drop every item of each selected table after its last query.
    pub table_drop: usize,
    /// Table-query or table-free field-arithmetic bytes.
    pub arithmetic: usize,
    /// Operand parking/restoration and result-to-altstack bytes.
    pub routing_output: usize,
    /// Number of coordinates for which a table is selected.
    pub table_coordinates: usize,
}

impl CostBreakdown {
    /// Total locking-script bytes in the batch multiplication fragment.
    pub fn total(self) -> usize {
        self.table_push + self.table_drop + self.arithmetic + self.routing_output
    }
}

impl std::ops::AddAssign for CostBreakdown {
    fn add_assign(&mut self, rhs: Self) {
        self.table_push += rhs.table_push;
        self.table_drop += rhs.table_drop;
        self.arithmetic += rhs.arithmetic;
        self.routing_output += rhs.routing_output;
        self.table_coordinates += rhs.table_coordinates;
    }
}

struct CoordinatePlan {
    script: Script,
    cost: CostBreakdown,
    table_items: u32,
    transient_items: u32,
}

fn canonical_full_query(modulus: u32, offset: u32) -> Script {
    let order = modulus - 1;
    let add_offset = || script! { if offset != 0 { { offset } OP_ADD } };
    script! {
        OP_2DUP OP_BOOLAND
        OP_IF
            { add_offset() } OP_PICK
            OP_SWAP { add_offset() } OP_PICK
            OP_ADD
            OP_DUP { modulus - 2 } OP_GREATERTHAN
            OP_IF
                { order } OP_SUB
            OP_ENDIF
            { order + offset } OP_ADD OP_PICK
        OP_ELSE
            OP_BOOLAND
        OP_ENDIF
    }
}

fn projective_query(modulus: u32, centered_exponents: bool, offset: u32) -> Script {
    let half = (modulus - 1) / 2;
    let add_offset = || script! { if offset != 0 { { offset } OP_ADD } };
    script! {
        OP_2DUP OP_BOOLAND
        OP_IF
            { modulus } OP_OVER OP_SUB
            OP_2DUP OP_GREATERTHAN OP_TOALTSTACK
            OP_MIN { add_offset() } OP_PICK
            OP_SWAP
            { modulus } OP_OVER OP_SUB
            OP_2DUP OP_GREATERTHAN
            OP_FROMALTSTACK OP_NUMNOTEQUAL OP_TOALTSTACK
            OP_MIN { add_offset() } OP_PICK

            OP_2DUP
            0 OP_LESSTHAN
            OP_SWAP
            0 OP_LESSTHAN
            OP_NUMNOTEQUAL
            OP_FROMALTSTACK OP_NUMNOTEQUAL OP_TOALTSTACK
            OP_ABS OP_SWAP OP_ABS OP_ADD

            { reduce_projective_sum(half) }
            { half + offset } OP_ADD OP_PICK
            OP_FROMALTSTACK

            if centered_exponents {
                OP_IF
                    OP_NEGATE
                OP_ENDIF
                OP_DUP 0 OP_LESSTHAN
                OP_IF
                    { modulus } OP_ADD
                OP_ENDIF
            } else {
                OP_IF
                    { modulus } OP_SWAP OP_SUB
                OP_ENDIF
            }
        OP_ELSE
            OP_BOOLAND
        OP_ENDIF
    }
}

fn table_entries(index: usize, selected: MulStrategy) -> Vec<i32> {
    match selected {
        MulStrategy::CanonicalFull => full_table_entries(index),
        MulStrategy::ProjectiveCanonical | MulStrategy::ProjectiveCentered => {
            projective_table_entries(index, selected == MulStrategy::ProjectiveCentered)
        }
        MulStrategy::Binary | MulStrategy::Ternary => unreachable!(),
    }
}

fn reusable_query(index: usize, selected: MulStrategy, offset: u32) -> Script {
    let modulus = MODULI[index];
    match selected {
        MulStrategy::CanonicalFull => canonical_full_query(modulus, offset),
        MulStrategy::ProjectiveCanonical | MulStrategy::ProjectiveCentered => {
            projective_query(modulus, selected == MulStrategy::ProjectiveCentered, offset)
        }
        MulStrategy::Binary | MulStrategy::Ternary => unreachable!(),
    }
}

fn table_free_plan(modulus: u32, products: u32) -> CoordinatePlan {
    let core = compact_binary_horner_coordinate_mul(modulus);
    let arithmetic = products as usize * core.clone().compile().len();
    CoordinatePlan {
        script: script! {
            for _ in 0..products {
                { core.clone() }
                OP_TOALTSTACK
            }
        },
        cost: CostBreakdown {
            arithmetic,
            routing_output: products as usize,
            ..CostBreakdown::default()
        },
        table_items: 0,
        transient_items: 4,
    }
}

fn table_plan(index: usize, selected: MulStrategy, products: u32) -> CoordinatePlan {
    let modulus = MODULI[index];
    let entries = table_entries(index, selected);
    let items = table_items(modulus, selected);
    let queries = (0..products)
        .map(|product| reusable_query(index, selected, 2 * (products - product - 1)))
        .collect::<Vec<_>>();
    let table_push = push_table_entries(&entries).compile().len();
    let table_drop = drop_items(items).compile().len();
    let arithmetic = queries
        .iter()
        .map(|query| query.clone().compile().len())
        .sum();
    CoordinatePlan {
        script: script! {
            // The table must sit below every pair for this coordinate. Moving
            // the pairs through the altstack installs it without transposing
            // either the input or the output batch.
            for _ in 0..2 * products {
                OP_TOALTSTACK
            }
            { push_table_entries(&entries) }
            for _ in 0..2 * products {
                OP_FROMALTSTACK
            }
            for query in queries {
                { query }
                OP_TOALTSTACK
            }
            { drop_items(items) }
        },
        cost: CostBreakdown {
            table_push,
            table_drop,
            arithmetic,
            routing_output: 5 * products as usize,
            table_coordinates: 1,
        },
        table_items: items,
        transient_items: 4,
    }
}

fn coordinate_plan(index: usize, products: u32) -> CoordinatePlan {
    let modulus = MODULI[index];
    match strategy(modulus) {
        MulStrategy::Binary => CoordinatePlan {
            script: script! {
                for _ in 0..products {
                    OP_BOOLAND OP_TOALTSTACK
                }
            },
            cost: CostBreakdown {
                arithmetic: products as usize,
                routing_output: products as usize,
                ..CostBreakdown::default()
            },
            table_items: 0,
            transient_items: 0,
        },
        MulStrategy::Ternary => {
            let query = ternary_coordinate_mul();
            CoordinatePlan {
                script: script! {
                    for _ in 0..products {
                        { query.clone() } OP_TOALTSTACK
                    }
                },
                cost: CostBreakdown {
                    arithmetic: products as usize * query.compile().len(),
                    routing_output: products as usize,
                    ..CostBreakdown::default()
                },
                table_items: 0,
                transient_items: 2,
            }
        }
        selected => {
            let table = table_plan(index, selected, products);
            let table_free = table_free_plan(modulus, products);
            if table.cost.total() < table_free.cost.total() {
                table
            } else {
                table_free
            }
        }
    }
}

fn plans(products: u32) -> Vec<CoordinatePlan> {
    MODULI
        .iter()
        .enumerate()
        .map(|(index, _)| coordinate_plan(index, products))
        .collect()
}

fn validate_products(products: u32) {
    assert!(products != 0, "prime RNS batch size must be positive");
    assert!(
        products <= MAX_PRODUCTS,
        "prime RNS batch multiplication exceeds Bitcoin Script's stack limit"
    );
}

fn calculated_peak(products: u32, plans: &[CoordinatePlan]) -> u64 {
    let input_items = 2 * u64::from(RESIDUE_COUNT) * u64::from(products);
    plans
        .iter()
        .enumerate()
        .fold(input_items, |peak, (index, plan)| {
            let live_before_coordinate = input_items - u64::from(products) * index as u64;
            peak.max(
                live_before_coordinate
                    + u64::from(plan.table_items)
                    + u64::from(plan.transient_items),
            )
        })
}

/// Return the exact byte decomposition selected for `products` products.
pub fn cost_breakdown(products: u32) -> CostBreakdown {
    validate_products(products);
    plans(products)
        .into_iter()
        .fold(CostBreakdown::default(), |mut total, plan| {
            total += plan.cost;
            total
        })
}

/// Return the moduli whose generated batch coordinates reuse a lookup table.
pub fn table_moduli(products: u32) -> Vec<u32> {
    validate_products(products);
    plans(products)
        .into_iter()
        .enumerate()
        .filter_map(|(index, plan)| (plan.table_items != 0).then_some(MODULI[index]))
        .collect()
}

/// Multiply `products` canonical RNS operand pairs in coordinate-major order.
///
/// `preserved_items` counts unrelated live main- and altstack items. Operands
/// are consumed; coordinate-major results are left on the altstack. No input
/// residue is range-checked by this fragment.
pub fn mul(products: u32, preserved_items: u32) -> Script {
    validate_products(products);
    let plans = plans(products);
    assert!(
        calculated_peak(products, &plans) + u64::from(preserved_items)
            <= u64::from(U31_LOOKUP_STACK_LIMIT),
        "prime RNS batch multiplication exceeds Bitcoin Script's stack limit"
    );
    script! {
        for plan in plans {
            { plan.script }
        }
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::BigUint;

    use super::*;
    use crate::arithmetic::rns::prime;

    fn test_values(
        products: u32,
    ) -> Vec<(
        [u32; MODULI.len()],
        [u32; MODULI.len()],
        [u32; MODULI.len()],
    )> {
        (0..products)
            .map(|product| {
                let lhs = BigUint::from(123_456_789u64 + 17 * u64::from(product));
                let rhs = BigUint::from(987_654_321u64 - 23 * u64::from(product));
                let expected = &lhs * &rhs;
                (
                    prime::encode(&lhs),
                    prime::encode(&rhs),
                    prime::encode(&expected),
                )
            })
            .collect()
    }

    fn execute_batch(products: u32) -> crate::support::execution::ExecuteInfo {
        let values = test_values(products);
        crate::support::execution::execute_script(script! {
            777
            888 OP_TOALTSTACK
            for coordinate in (0..MODULI.len()).rev() {
                for product in (0..products as usize).rev() {
                    { values[product].0[coordinate] }
                    { values[product].1[coordinate] }
                }
            }
            { mul(products, 2) }
            for coordinate in (0..MODULI.len()).rev() {
                for product in (0..products as usize).rev() {
                    OP_FROMALTSTACK
                    { values[product].2[coordinate] }
                    OP_EQUALVERIFY
                }
            }
            OP_FROMALTSTACK 888 OP_EQUALVERIFY
            777 OP_EQUALVERIFY
            OP_TRUE
        })
    }

    #[test]
    fn coordinate_major_batches_are_correct_and_preserve_state() {
        for (products, expected_peak) in [(1, 185), (2, 380), (6, 902)] {
            let result = execute_batch(products);
            assert!(result.success, "batch size {products} failed: {result}");
            assert_eq!(result.stats.max_nb_stack_items, expected_peak);
        }
    }

    #[test]
    fn exact_cost_breakdowns_match_generated_scripts() {
        let expected = [
            (1, 392, 165, 14_664, 123, 12, 15_344),
            (2, 2_223, 709, 26_308, 350, 25, 29_590),
            (3, 6_928, 2_000, 31_994, 729, 42, 41_651),
            (4, 15_052, 4_115, 30_856, 1_244, 59, 51_267),
            (5, 20_592, 5_417, 30_922, 1_715, 67, 58_646),
            (6, 25_510, 6_521, 30_229, 2_202, 73, 64_462),
        ];
        for (products, push, drop, arithmetic, routing, coordinates, total) in expected {
            let cost = cost_breakdown(products);
            assert_eq!(cost.table_push, push);
            assert_eq!(cost.table_drop, drop);
            assert_eq!(cost.arithmetic, arithmetic);
            assert_eq!(cost.routing_output, routing);
            assert_eq!(cost.table_coordinates, coordinates);
            assert_eq!(cost.total(), total);
            assert_eq!(mul(products, 0).compile().len(), total);
        }
    }

    #[test]
    #[should_panic(
        expected = "prime RNS batch multiplication exceeds Bitcoin Script's stack limit"
    )]
    fn seven_products_are_rejected() {
        let _ = mul(7, 0);
    }

    #[test]
    #[should_panic(
        expected = "prime RNS batch multiplication exceeds Bitcoin Script's stack limit"
    )]
    fn excessive_preserved_depth_is_rejected() {
        let _ = mul(6, U31_LOOKUP_STACK_LIMIT - 900 + 1);
    }
}
