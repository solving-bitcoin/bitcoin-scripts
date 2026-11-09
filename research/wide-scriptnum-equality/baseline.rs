// Split a signed operand into a signed quotient and nonnegative remainder
// in radix 2^30. Every arithmetic operation has a four-byte result.
const RADIX: i32 = 1 << 30;

fn split() -> Script {
    script! {
        OP_DUP 0 OP_LESSTHAN
        OP_IF
            {RADIX} OP_ADD
            OP_DUP 0 OP_LESSTHAN
            OP_IF {RADIX} OP_ADD -2
            OP_ELSE -1
            OP_ENDIF
        OP_ELSE
            OP_DUP {RADIX} OP_GREATERTHANOREQUAL
            OP_IF {RADIX} OP_SUB 1
            OP_ELSE 0
            OP_ENDIF
        OP_ENDIF
        OP_SWAP
    }
}

fn add_as_limbs() -> Script {
    script! {
        {split()} OP_TOALTSTACK OP_TOALTSTACK
        {split()} OP_FROMALTSTACK OP_ROT OP_ADD OP_SWAP OP_FROMALTSTACK OP_ADD
        OP_DUP {RADIX} OP_GREATERTHANOREQUAL
        OP_IF {RADIX} OP_SUB OP_SWAP OP_1ADD OP_SWAP OP_ENDIF
    }
}

/// Verify the same exact relation while keeping both sums in two numeric limbs.
pub fn verify_equal_sums_with_limbs() -> Script {
    script! {
        {add_as_limbs()} OP_TOALTSTACK OP_TOALTSTACK
        {add_as_limbs()} OP_FROMALTSTACK OP_FROMALTSTACK
        OP_ROT OP_NUMEQUALVERIFY OP_NUMEQUALVERIFY
    }
}
