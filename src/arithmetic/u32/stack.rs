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

fn certify_compressed_word() -> Script {
    script! {
        OP_DUP
        OP_SIZE
        5
        OP_EQUAL
        OP_IF
            -2147483648
            OP_EQUALVERIFY
        OP_ELSE
            OP_DUP
            0
            OP_ADD
            OP_EQUALVERIFY
        OP_ENDIF
    }
}

/// Compares two canonical compressed u32 ScriptNums for equality.
pub fn u32_compressed_equal() -> Script {
    script! {
        { certify_compressed_word() }
        OP_TOALTSTACK
        { certify_compressed_word() }
        OP_FROMALTSTACK
        OP_EQUAL
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
    use crate::support::execution::{execute_script_with_inputs_strict, run};

    fn scriptnum(value: u32) -> Vec<u8> {
        let mut bytes = [0u8; 8];
        let length = bitcoin::script::write_scriptint(&mut bytes, i64::from(value as i32));
        bytes[..length].to_vec()
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

    #[test]
    fn test_u32_compressed_equal_boundaries() {
        for &(a, b) in &[
            (0, 0),
            (0, 1),
            (0x7fff_ffff, 0x7fff_ffff),
            (0x8000_0000, 0x8000_0000),
            (u32::MAX, u32::MAX),
            (u32::MAX, 0),
        ] {
            let result = execute_script_with_inputs_strict(
                script! {
                    { u32_compressed_equal() }
                    { (a == b) as u32 }
                    OP_EQUAL
                },
                vec![scriptnum(b), scriptnum(a)],
            );
            assert!(
                result.success,
                "compressed equality failed for {a:08x} == {b:08x}: {result}"
            );
        }
    }

    #[test]
    fn test_u32_compressed_equal_rejects_noncanonical_inputs() {
        for inputs in [
            vec![vec![1, 0], scriptnum(1)],
            vec![vec![0, 0, 0, 0x80], scriptnum(0)],
            vec![vec![1, 0, 0, 0, 0], scriptnum(0)],
        ] {
            let result =
                execute_script_with_inputs_strict(script! { { u32_compressed_equal() } }, inputs);
            assert!(
                result.error.is_some(),
                "accepted malformed compressed input: {result}"
            );
        }
    }
}
