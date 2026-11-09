pub fn encode(value: u8) -> u8 {
    let mut word = 0u8;
    for (bit, position) in [3, 5, 6, 7].into_iter().enumerate() {
        word |= ((value >> bit) & 1) << (position - 1);
    }
    let syndrome = (1..=7)
        .filter(|position| word & (1 << (position - 1)) != 0)
        .fold(0, |acc, position| acc ^ position);
    for position in [1, 2, 4] {
        if syndrome & position != 0 {
            word |= 1 << (position - 1);
        }
    }
    word | (((word.count_ones() & 1) as u8) << 7)
}

pub fn nearest(byte: u8) -> Option<u8> {
    let mut matches = (0..16).filter(|&value| (encode(value) ^ byte).count_ones() <= 1);
    let nearest = matches.next();
    assert!(matches.next().is_none());
    nearest
}

fn push_table() -> Script {
    script! {
        for byte in (0..=255u8).rev() {
            {nearest(byte).map_or(-1, i32::from)}
        }
    }
}

fn lookup_checked() -> Script {
    script! {
        OP_PICK
        OP_DUP 0 OP_GREATERTHANOREQUAL OP_VERIFY
    }
}

fn drop_table() -> Script {
    script! {
        for _ in 0..256 {OP_DROP}
    }
}

pub fn decode_with_table() -> Script {
    script! {
        {verify_canonical_byte()} OP_TOALTSTACK
        {push_table()} OP_FROMALTSTACK {lookup_checked()}
        OP_TOALTSTACK {drop_table()} OP_FROMALTSTACK
    }
}

pub fn decode_batch_with_table(n: u32) -> Script {
    script! {
        {push_table()}
        for _ in 0..n {
            256 OP_ROLL {verify_canonical_byte()} {lookup_checked()}
            OP_TOALTSTACK
        }
        {drop_table()}
        for _ in 0..n {
            OP_FROMALTSTACK
        }
    }
}
