mod full {
    include!("../../src/arithmetic/u4/xor_reduce/full.rs");
}

pub fn full_table(n: u32) -> Script {
    full::reduce_with_validation(n, verify_canonical_nibble())
}

pub fn triangular_table(n: u32) -> Script {
    script! {
        for _ in 0..n {
            {verify_canonical_nibble()}
            OP_TOALTSTACK
        }
        {u4_push_half_xor_table()} {u4_push_half_lookup()}
        for _ in 0..n {OP_FROMALTSTACK}
        for reduction in 1..n {
            {u4_half_table_operation(n - reduction + 1)}
        }
        OP_TOALTSTACK {u4_drop_half_lookup()} {u4_drop_half_table()} OP_FROMALTSTACK
    }
}
