mod packed {
    include!("../../src/arithmetic/u4/argmin/packed.rs");
}

pub fn direct_state(n: u32) -> Script {
    script! {
        16 {n}
        for position in (0..n).rev() {
            2 OP_ROLL {verify_canonical_nibble()}
            OP_DUP 3 OP_PICK OP_LESSTHANOREQUAL
            OP_IF OP_NIP OP_NIP {position}
            OP_ELSE OP_DROP OP_ENDIF
        }
    }
}

pub fn packed_shift(n: u32) -> Script {
    let stride = n.next_power_of_two();
    script! {
        {16 * stride}
        for position in (0..n).rev() {
            OP_SWAP {verify_canonical_nibble()}
            {mul_by_constant(stride)}
            {position} OP_ADD OP_MIN
        }
        {packed::split_score(stride)}
    }
}
