/// Preserve the low half and look up exact raw bytes in the high half.
pub fn convert_with_high_table() -> Script {
    script! {
        {verify_canonical_byte()}
        OP_DUP 128 OP_LESSTHAN
        OP_IF
            OP_DUP OP_0NOTEQUAL
            OP_NOTIF OP_DROP {vec![0u8]} OP_ENDIF
        OP_ELSE
            128 OP_SUB OP_TOALTSTACK
            for byte in (128u8..=255).rev() {{vec![byte]}}
            OP_FROMALTSTACK OP_PICK OP_TOALTSTACK
            for _ in 0..128 {OP_DROP}
            OP_FROMALTSTACK
        OP_ENDIF
    }
}
