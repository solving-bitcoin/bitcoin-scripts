use super::u4_std::{u4_drop, CalculateOffset};
use crate::script::*;
use bitcoin::opcodes::all::*;

pub fn u4_push_quotient_table() -> Script {
    script! {
        for i in (0..=3).rev() {
            { i }
            OP_DUP
            OP_2DUP
            OP_3DUP
            OP_3DUP
            OP_3DUP
            OP_3DUP
        }
    }
}

pub fn u4_push_quotient_table_5() -> Script {
    script! {
        for i in (0..=4).rev() {
            { i }
            OP_DUP
            OP_2DUP
            OP_3DUP
            OP_3DUP
            OP_3DUP
            OP_3DUP
        }
    }
}

pub fn u4_drop_quotient_table() -> Script {
    u4_drop(64)
}

pub fn u4_push_modulo_table() -> Script {
    script! {
        for i in (0..64).rev() {
            { i % 16 }
        }
    }
}

pub fn u4_push_modulo_table_5() -> Script {
    script! {
        for i in (0..80).rev() {
            { i % 16 }
        }
    }
}

pub fn u4_drop_modulo_table() -> Script {
    u4_drop(64)
}

pub fn u4_push_add_tables() -> Script {
    script! {
        { u4_push_modulo_table() }
        { u4_push_quotient_table() }
    }
}

pub fn u4_drop_add_tables() -> Script {
    script! {
        { u4_drop_quotient_table() }
        { u4_drop_modulo_table() }
    }
}

pub fn u4_arrange_nibbles(nibble_count: u32, mut bases: Vec<u32>) -> Script {
    bases.sort();
    bases.reverse();
    for base_i in &mut bases {
        *base_i += nibble_count - 1;
    }
    script! {
        for i in 0..nibble_count {
            for (n, base) in bases.iter().enumerate() {
                {  (base - i)  +  ((n as u32 + 1) * (i + 1)) - 1 }
                OP_ROLL
            }
        }
    }
}

pub fn u4_add_carry_nested(current: u32, limit: u32) -> Script {
    script! {
        OP_DUP
        OP_16
        OP_GREATERTHANOREQUAL
        OP_IF
            OP_16
            OP_SUB
            if current + 1 == limit {
                { current }
            } else {
                { u4_add_carry_nested(current+1, limit)}
            }
        OP_ELSE
            { current }
        OP_ENDIF
    }
}

pub fn u4_add_nested(current: u32, limit: u32) -> Script {
    script! {
        OP_DUP
        OP_16
        OP_GREATERTHANOREQUAL
        OP_IF
            OP_16
            OP_SUB
            if current + 1 < limit {
                { u4_add_nested(current + 1, limit)}
            }
        OP_ENDIF
    }
}

pub fn u4_add_no_table_internal(nibble_count: u32, number_count: u32) -> Script {
    script! {
        for i in 0..nibble_count {
            for _ in 0..number_count-1 {
                OP_ADD
            }
            if i < nibble_count - 1 {
                { u4_add_carry_nested(0, number_count) }
                OP_SWAP
                OP_TOALTSTACK
                OP_ADD
            } else {
                { u4_add_nested(0, number_count) }
                OP_TOALTSTACK
            }
        }
    }
}

pub fn u4_add_internal(nibble_count: u32, number_count: u32, tables_offset: u32) -> Script {
    assert!(number_count < 5);
    let quotient_table_size = 64;
    let mut offset_calc: i32 = 0;
    script! {
        for i in 0..nibble_count {
            if i > 0 {
                { offset_calc.modify(OP_ADD) }
            }

            for _ in 0..number_count-1 {
                { offset_calc.modify(OP_ADD) }
            }

            if i < nibble_count -1 {
                { offset_calc.modify( OP_DUP) }
            }

            {  (offset_calc - 1)  + tables_offset as i32 + quotient_table_size }
            OP_ADD
            { offset_calc.modify(OP_PICK) }
            { offset_calc.modify(OP_TOALTSTACK) }

            if i < nibble_count - 1 {
                { (offset_calc - 1) + tables_offset as i32 }
                OP_ADD
                { offset_calc.modify(OP_PICK) }
            }
        }
    }
}

pub fn u4_add_with_table(nibble_count: u32, bases: Vec<u32>, tables_offset: u32) -> Script {
    let numbers = bases.len() as u32;
    script! {
        { u4_arrange_nibbles(nibble_count, bases)  }
        { u4_add_internal(nibble_count, numbers, tables_offset) }
    }
}

pub fn u4_add_no_table(nibble_count: u32, bases: Vec<u32>) -> Script {
    let numbers = bases.len() as u32;
    script! {
        { u4_arrange_nibbles(nibble_count, bases)  }
        { u4_add_no_table_internal(nibble_count, numbers) }
    }
}

pub fn u4_add(
    nibble_count: u32,
    bases: Vec<u32>,
    tables_offset: u32,
    use_add_table: bool,
) -> Script {
    if use_add_table {
        u4_add_with_table(nibble_count, bases, tables_offset)
    } else {
        u4_add_no_table(nibble_count, bases)
    }
}

#[cfg(test)]
mod tests {
    use crate::script::*;
    use crate::u4::{u4_add::*, u4_std::u4_number_to_nibble};
    use rand::Rng;

    #[test]
    fn test_add_no_table() {
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            for len in 2..5 {
                let vars: Vec<u32> = (0..len).map(|_| rng.gen()).collect();
                let result = vars.iter().fold(0_u64, |sum, &x| sum + x as u64) % (1_u64 << 32);
                let script = script! {
                    for x in vars {
                        { u4_number_to_nibble(x) }
                    }
                    { u4_add_no_table(8,  (0..).step_by(8).take(len.try_into().unwrap()).collect()) }
                    { u4_number_to_nibble(result.try_into().unwrap()) }
                    for _ in 0..8 {
                        OP_FROMALTSTACK
                    }
                    for i in 0..8 {
                        { 8 - i }
                        OP_ROLL
                        OP_EQUALVERIFY
                    }
                    OP_TRUE
                };
                crate::run(script);
            }
        }
    }

    #[test]
    fn test_add_with_table() {
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            for len in 2..5 {
                let vars: Vec<u32> = (0..len).map(|_| rng.gen()).collect();
                let result = vars.iter().fold(0_u64, |sum, &x| sum + x as u64) % (1_u64 << 32);
                let script = script! {
                    { u4_push_add_tables() }
                    for x in vars {
                        { u4_number_to_nibble(x) }
                    }
                    { u4_add_with_table(8,  (0..).step_by(8).take(len.try_into().unwrap()).collect(), len * 8) }
                    { u4_drop_add_tables() }
                    { u4_number_to_nibble(result.try_into().unwrap()) }
                    for _ in 0..8 {
                        OP_FROMALTSTACK
                    }
                    for i in 0..8 {
                        { 8 - i }
                        OP_ROLL
                        OP_EQUALVERIFY
                    }
                    OP_TRUE
                };
                crate::run(script);
            }
        }
    }
}
