use crate::support::script::*;
use bitcoin::{opcodes::all::*, Opcode};

pub fn u4_toaltstack(n: u32) -> Script {
    script! {
        for _ in 0..n {
            OP_TOALTSTACK
        }
    }
}

pub fn u4_fromaltstack(n: u32) -> Script {
    script! {
        for _ in 0..n {
            OP_FROMALTSTACK
        }
    }
}

pub fn u4_copy_u32_from(address: u32) -> Script {
    script! {
        for _ in 0..8 {
            { address + 7 }
            OP_PICK
        }
    }
}

pub fn u4_move_u32_from(address: u32) -> Script {
    script! {
        for _ in 0..8 {
            { address + 7 }
            OP_ROLL
        }
    }
}

pub fn verify_n(n: u32) -> Script {
    script! {
        for i in 0..n {
            { n - i}
            OP_ROLL
            OP_EQUALVERIFY
        }
    }
}

pub fn u4_u32_verify_from_altstack() -> Script {
    script! {
        for _ in 0..8 {
            OP_FROMALTSTACK
        }

        for i in 0..8 {
            { 8 - i}
            OP_ROLL
            OP_EQUALVERIFY
        }
    }
}

pub fn u4_drop(n: u32) -> Script {
    script! {
        for _ in 0..n / 2 {
            OP_2DROP
        }
        if n & 1 == 1 {
            OP_DROP
        }
    }
}

pub fn u4_number_to_nibble(n: u32) -> Script {
    script! {
       for i in (0..8).rev() {
            { (n >> (i * 4)) & 0xF }
        }
    }
}

pub fn u4_hex_to_nibbles(hex_str: &str) -> Script {
    let nibbles: Result<Vec<u8>, std::num::ParseIntError> = hex_str
        .chars()
        .map(|c| u8::from_str_radix(&c.to_string(), 16))
        .collect();
    let nibbles = nibbles.unwrap();
    script! {
        for nibble in nibbles {
            { nibble }
        }
    }
}

/// Pack `high | low` nibbles into one byte-valued ScriptNum.
///
/// With `check_inputs`, both inputs are constrained to `0..=15`. Without it,
/// the caller must already have established that invariant.
pub fn u4_pair_to_u8(check_inputs: bool) -> Script {
    script! {
        if check_inputs {
            OP_DUP 0 16 OP_WITHIN OP_VERIFY
            1 OP_PICK 0 16 OP_WITHIN OP_VERIFY
        }
        OP_SWAP
        OP_DUP OP_ADD
        OP_DUP OP_ADD
        OP_DUP OP_ADD
        OP_DUP OP_ADD
        OP_ADD
    }
}

pub fn u4_repeat_number(n: u32, count: u32) -> Script {
    match count {
        0 => script! {},
        1 => script! { { n } },
        2 => script! { { n } OP_DUP },
        _ => {
            let diff = count - 2;
            let count = diff / 2;
            let rem = diff % 2;
            script! {
                {u4_repeat_number(n, 2)}
                for _ in 0..count {
                    OP_2DUP
                }
                if rem == 1 {
                    OP_DUP
                }
            }
        }
    }
}

pub trait CalculateOffset {
    fn modify(&mut self, element: Opcode) -> Script;
}

impl CalculateOffset for i32 {
    fn modify(&mut self, element: Opcode) -> Script {
        match element {
            OP_TOALTSTACK | OP_ADD => *self -= 1,
            OP_PICK => {}
            OP_DUP => *self += 1,
            _ => {
                panic!("unexpected opcode: {:?}", element);
            }
        }

        Script::new("").push_opcode(element)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::{u4_hex_to_nibbles, u4_repeat_number};
    use crate::arithmetic::u4::stack::u4_number_to_nibble;

    #[test]
    fn test_repeat() {
        for n in 0..30 {
            let script = script! {
                { u4_repeat_number(1, n) }
                for _ in 0..n {
                    OP_DROP
                }
                OP_TRUE
            };
            crate::support::execution::run(script);
        }
    }

    #[test]
    fn test_number_to_nibble() {
        let script = script! {
            { u4_number_to_nibble(0xfedc8765) }
            5
            OP_EQUALVERIFY
            6
            OP_EQUALVERIFY
            7
            OP_EQUALVERIFY
            8
            OP_EQUALVERIFY
            12
            OP_EQUALVERIFY
            13
            OP_EQUALVERIFY
            14
            OP_EQUALVERIFY
            15
            OP_EQUALVERIFY
            OP_TRUE
        };
        crate::support::execution::run(script);
    }

    #[test]
    fn test_hex_to_nibble() {
        let script = script! {
            { u4_hex_to_nibbles("fedc8765")}
            5
            OP_EQUALVERIFY
            6
            OP_EQUALVERIFY
            7
            OP_EQUALVERIFY
            8
            OP_EQUALVERIFY
            12
            OP_EQUALVERIFY
            13
            OP_EQUALVERIFY
            14
            OP_EQUALVERIFY
            15
            OP_EQUALVERIFY
            OP_TRUE
        };
        crate::support::execution::run(script);
    }

    #[test]
    fn packs_all_checked_nibble_pairs() {
        for byte in 0..=u8::MAX {
            let result = crate::support::execution::execute_script(script! {
                { (byte >> 4) as u32 }
                { (byte & 0x0f) as u32 }
                { u4_pair_to_u8(true) }
                { byte as u32 } OP_EQUAL
            });
            assert!(result.success, "failed to pack byte {byte:#x}: {result}");
        }
    }

    #[test]
    fn checked_pair_rejects_malformed_nibbles_and_preserves_state() {
        for (high, low) in [(-1, 0), (0, 16), (16, 0), (0, -1)] {
            let result = crate::support::execution::execute_script(script! {
                { high }
                { low }
                { u4_pair_to_u8(true) }
                OP_TRUE
            });
            assert!(!result.success, "accepted malformed pair {high}, {low}");
        }

        let result = crate::support::execution::execute_script(script! {
            OP_9
            0xa
            0xb
            { u4_pair_to_u8(true) }
            171 OP_EQUALVERIFY
            9 OP_EQUAL
        });
        assert!(
            result.success,
            "pair packing changed preserved state: {result}"
        );
    }

    #[test]
    fn unchecked_pair_requires_the_caller_invariant() {
        let result = crate::support::execution::execute_script(script! {
            0 -1
            { u4_pair_to_u8(false) }
            -1 OP_EQUAL
        });
        assert!(
            result.success,
            "unchecked pair did not preserve hostile item: {result}"
        );
    }
}
