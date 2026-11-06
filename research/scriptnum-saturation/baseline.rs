// Detect overflow from the canonical width of the sum. Only the saved
// operand is read numerically if the sum occupies five bytes.
pub fn saturating_add_by_width() -> Script {
    let max = 0x7fff_ffffi32;
    script! {
        OP_OVER OP_SWAP OP_ADD
        OP_SIZE 4 OP_GREATERTHAN
        OP_IF
            OP_DROP 0 OP_LESSTHAN
            OP_IF {-max} OP_ELSE {max} OP_ENDIF
        OP_ELSE
            OP_NIP
        OP_ENDIF
    }
}
