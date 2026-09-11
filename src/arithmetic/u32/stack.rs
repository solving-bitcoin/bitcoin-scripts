use crate::support::script::*;
use crate::support::script_ops::{push_to_stack, OP_256MUL, OP_4DUP};

pub fn u32_push(value: u32) -> Script {
    script! {
        if ((value >> 24) & 0xff) == ((value >> 16) & 0xff) &&
            ((value >> 24) & 0xff) == ((value >> 8) & 0xff) &&
            ((value >> 24) & 0xff) == (value & 0xff) {
                { push_to_stack(((value >> 24) & 0xff) as usize, 4) }
        }
        else{
                {(value >> 24) & 0xff}
                {(value >> 16) & 0xff}
                {(value >>  8) & 0xff}
                {value & 0xff}
        }
    }
}

pub fn u32_equalverify() -> Script {
    script! {
        4
        OP_ROLL
        OP_EQUALVERIFY
        3
        OP_ROLL
        OP_EQUALVERIFY
        OP_ROT
        OP_EQUALVERIFY
        OP_EQUALVERIFY
    }
}

pub fn u32_equal() -> Script {
    script! {
        4
        OP_ROLL
        OP_EQUAL OP_TOALTSTACK
        3
        OP_ROLL
        OP_EQUAL OP_TOALTSTACK
        OP_ROT
        OP_EQUAL OP_TOALTSTACK
        OP_EQUAL
        OP_FROMALTSTACK OP_BOOLAND
        OP_FROMALTSTACK OP_BOOLAND
        OP_FROMALTSTACK OP_BOOLAND
    }
}

pub fn u32_notequal() -> Script {
    script! {
        { u32_equal() }
        OP_NOT
    }
}

pub fn u32_toaltstack() -> Script {
    script! {
        OP_TOALTSTACK
        OP_TOALTSTACK
        OP_TOALTSTACK
        OP_TOALTSTACK
    }
}

pub fn u32_fromaltstack() -> Script {
    script! {
        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_FROMALTSTACK
        OP_FROMALTSTACK
    }
}

pub fn u32_dup() -> Script {
    script! { OP_4DUP }
}

pub fn u32_drop() -> Script {
    script! {
        OP_2DROP
        OP_2DROP
    }
}

pub fn u32_roll(n: u32) -> Script {
    let n = (n + 1) * 4 - 1;
    script! {
        {n} OP_ROLL
        {n} OP_ROLL
        {n} OP_ROLL
        {n} OP_ROLL
    }
}

pub fn u32_pick(n: u32) -> Script {
    let n = (n + 1) * 4 - 1;
    script! {
        {n} OP_PICK
        {n} OP_PICK
        {n} OP_PICK
        {n} OP_PICK
    }
}

/// Compresses the top u32 element into a single element
/// Compress four most-significant-byte-first byte items into one ScriptNum.
///
/// The unsigned value is encoded in the minimal ScriptNum width, so values
/// whose high bit is set may use a fifth sign byte.
pub fn u32_compress() -> Script {
    script! {
        OP_SWAP OP_2SWAP OP_SWAP
        0x80
        OP_2DUP OP_GREATERTHANOREQUAL
        OP_DUP OP_TOALTSTACK
        OP_IF OP_SUB OP_ELSE OP_DROP OP_ENDIF
        OP_256MUL OP_ADD
        OP_256MUL OP_ADD
        OP_256MUL OP_ADD
        OP_FROMALTSTACK
        OP_IF 0x7FFFFFFF OP_SUB OP_1SUB OP_ENDIF
    }
}

/// Expand a ScriptNum of at most five bytes into four byte items.
///
/// The caller must enforce the intended unsigned range and canonical encoding
/// when those properties are part of the protocol boundary.
pub fn u32_uncompress() -> Script {
    script! {
        OP_SIZE OP_5 OP_EQUAL
        OP_TUCK OP_IF
            OP_DROP OP_0
        OP_ELSE
            OP_TUCK OP_GREATERTHAN
            OP_TUCK OP_IF 0x7FFFFFFF OP_ADD OP_1ADD OP_ENDIF
        OP_ENDIF
        OP_SWAP OP_TOALTSTACK
        for i in 1..8 {
            { 1 << (31 - i) } OP_2DUP OP_GREATERTHANOREQUAL
            OP_FROMALTSTACK OP_DUP OP_ADD OP_OVER OP_ADD OP_TOALTSTACK
            OP_IF OP_SUB OP_ELSE OP_DROP OP_ENDIF
        }
        { 1 << 23 } OP_2DUP OP_GREATERTHANOREQUAL OP_DUP OP_TOALTSTACK
        OP_IF OP_SUB OP_ELSE OP_DROP OP_ENDIF
        for i in 1..8 {
            { 1 << (23 - i) } OP_2DUP OP_GREATERTHANOREQUAL
            OP_FROMALTSTACK OP_DUP OP_ADD OP_OVER OP_ADD OP_TOALTSTACK
            OP_IF OP_SUB OP_ELSE OP_DROP OP_ENDIF
        }
        { 1 << 15 } OP_2DUP OP_GREATERTHANOREQUAL OP_DUP OP_TOALTSTACK
        OP_IF OP_SUB OP_ELSE OP_DROP OP_ENDIF
        for i in 1..8 {
            { 1 << (15 - i) } OP_2DUP OP_GREATERTHANOREQUAL
            OP_FROMALTSTACK OP_DUP OP_ADD OP_OVER OP_ADD OP_TOALTSTACK
            OP_IF OP_SUB OP_ELSE OP_DROP OP_ENDIF
        }
        OP_FROMALTSTACK OP_FROMALTSTACK OP_FROMALTSTACK
        OP_SWAP OP_2SWAP OP_SWAP
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::execution::run;

    #[test]
    fn compressed_u32_round_trips_scriptnum_boundaries() {
        for value in [
            0,
            1,
            0x7f,
            0x80,
            0xff,
            0x100,
            0x7fff_ffff,
            0x8000_0000,
            u32::MAX,
        ] {
            let result = crate::support::execution::execute_script(script! {
                { u32_push(value) }
                { u32_compress() }
                { u32_uncompress() }
                { u32_push(value) }
                { u32_equalverify() }
                OP_TRUE
            });
            assert!(
                result.success,
                "round trip failed for {value:#x}: {result:?}"
            );
        }
    }

    #[test]
    fn uncompress_rejects_scriptnums_wider_than_five_bytes() {
        let result = crate::support::execution::execute_script_with_inputs(
            script! {
                { u32_uncompress() }
                { u32_drop() }
                OP_TRUE
            },
            vec![vec![0, 0, 0, 0, 0, 0]],
        );
        assert!(!result.success, "accepted an oversized ScriptNum: {result}");
    }

    #[test]
    fn test_u32_notequal() {
        for (a, b) in [
            (0, 0),
            (0, 1),
            (0xff, 0x100),
            (u32::MAX, u32::MAX),
            (u32::MAX, 0),
        ] {
            let script = script! {
                { u32_push(a) }
                { u32_push(b) }
                { u32_notequal() }
                { (a != b) as u32 }
                OP_EQUAL
            };
            run(script);
        }
    }
}
