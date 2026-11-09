use super::{mul_by_constant, script, Script};

pub(super) fn decode_with(marker: Script, byte: Script) -> Script {
    script! {
        OP_DUP {marker} OP_EQUAL
        OP_IF
            OP_DROP {byte.clone()} OP_SWAP {byte.clone()}
            {mul_by_constant(256)} OP_ADD
            OP_DUP 253 OP_GREATERTHANOREQUAL OP_VERIFY
        OP_ELSE
            {byte}
            OP_DUP 253 OP_LESSTHAN OP_VERIFY
        OP_ENDIF
    }
}
