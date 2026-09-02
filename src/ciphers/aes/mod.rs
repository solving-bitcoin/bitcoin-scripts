//! AES-128 encryption for one 128-bit block.
//!
//! The Script generator keeps one shared 832-item lookup memory for the whole
//! cipher. State bytes are represented as high/low nibble pairs so every XOR
//! can use the same 4-bit table. SubBytes is fused with ShiftRows, and
//! MixColumns is fused with AddRoundKey.

use bitcoin::{
    opcodes::{
        all::{
            OP_2DROP, OP_2DUP, OP_2OVER, OP_3DUP, OP_ADD, OP_DUP, OP_FROMALTSTACK, OP_GREATERTHAN,
            OP_OVER, OP_PICK, OP_SUB, OP_SWAP, OP_TOALTSTACK,
        },
        Opcode,
    },
    script::Builder,
};

use crate::support::script::Script;

const BLOCK_BYTES: usize = 16;
const STATE_NIBBLES: usize = 32;
const TABLE_ITEMS: usize = 832;

// The smallest-depth slots serve the hottest operations. In particular every
// variable XOR first reads XOR_SHIFT, so keeping it directly below the state
// saves a byte at each of those reads.
const XOR_SHIFT_ADDR: i32 = STATE_NIBBLES as i32;
const XTIME_HI_ADDR: i32 = XOR_SHIFT_ADDR + 16;
const XTIME_DOUBLE_LO_ADDR: i32 = XTIME_HI_ADDR + 16;
const XTIME_BIAS_LO_ADDR: i32 = XTIME_DOUBLE_LO_ADDR + 16;
const XOR_ADDR: i32 = XTIME_BIAS_LO_ADDR + 16;
const SBOX_HI_ADDR: i32 = XOR_ADDR + 256;
const SBOX_LO_ADDR: i32 = SBOX_HI_ADDR + 256;

const SHIFT_ROWS: [usize; 16] = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11];

const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// Expand an AES-128 key into the 11 round keys used by encryption.
pub fn aes128_expand_key(key: [u8; 16]) -> [[u8; 16]; 11] {
    let mut expanded = [0u8; 176];
    expanded[..16].copy_from_slice(&key);

    let mut generated = 16;
    let mut round = 0;
    let mut word = [0u8; 4];
    while generated < expanded.len() {
        word.copy_from_slice(&expanded[generated - 4..generated]);
        if generated % 16 == 0 {
            word.rotate_left(1);
            for byte in &mut word {
                *byte = SBOX[*byte as usize];
            }
            word[0] ^= RCON[round];
            round += 1;
        }
        for byte in word {
            expanded[generated] = expanded[generated - 16] ^ byte;
            generated += 1;
        }
    }

    std::array::from_fn(|round| {
        let mut key = [0u8; 16];
        key.copy_from_slice(&expanded[16 * round..16 * (round + 1)]);
        key
    })
}

fn xtime(byte: u8) -> u8 {
    (byte << 1) ^ if byte & 0x80 != 0 { 0x1b } else { 0 }
}

fn sub_bytes(state: &mut [u8; 16]) {
    for byte in state {
        *byte = SBOX[*byte as usize];
    }
}

fn shift_rows(state: &mut [u8; 16]) {
    let source = *state;
    for (destination, input) in SHIFT_ROWS.into_iter().enumerate() {
        state[destination] = source[input];
    }
}

fn mix_columns(state: &mut [u8; 16]) {
    for column in 0..4 {
        let i = 4 * column;
        let [a, b, c, d] = [state[i], state[i + 1], state[i + 2], state[i + 3]];
        state[i] = xtime(a) ^ xtime(b) ^ b ^ c ^ d;
        state[i + 1] = a ^ xtime(b) ^ xtime(c) ^ c ^ d;
        state[i + 2] = a ^ b ^ xtime(c) ^ xtime(d) ^ d;
        state[i + 3] = xtime(a) ^ a ^ b ^ c ^ xtime(d);
    }
}

fn add_round_key(state: &mut [u8; 16], key: &[u8; 16]) {
    for (state, key) in state.iter_mut().zip(key) {
        *state ^= key;
    }
}

/// Reference AES-128 encryption of one 16-byte block.
pub fn aes128_encrypt_ref(key: [u8; 16], plaintext: [u8; 16]) -> [u8; 16] {
    let round_keys = aes128_expand_key(key);
    let mut state = plaintext;
    add_round_key(&mut state, &round_keys[0]);
    for round_key in &round_keys[1..10] {
        sub_bytes(&mut state);
        shift_rows(&mut state);
        mix_columns(&mut state);
        add_round_key(&mut state, round_key);
    }
    sub_bytes(&mut state);
    shift_rows(&mut state);
    add_round_key(&mut state, &round_keys[10]);
    state
}

/// Convert bytes into high/low nibble pairs in AES state order.
pub fn bytes_to_nibbles(bytes: [u8; 16]) -> [u8; 32] {
    std::array::from_fn(|i| {
        let byte = bytes[i / 2];
        if i & 1 == 0 {
            byte >> 4
        } else {
            byte & 0xf
        }
    })
}

#[derive(Clone, Copy)]
enum Token {
    Push(i32),
    Op(Opcode),
}

#[derive(Clone, Default)]
struct Program(Vec<Token>);

impl Program {
    fn push(&mut self, value: i32) {
        self.0.push(Token::Push(value));
    }

    fn op(&mut self, opcode: Opcode) {
        self.0.push(Token::Op(opcode));
    }

    fn extend(&mut self, other: Program) {
        self.0.extend(other.0);
    }

    fn into_script(self, name: &str) -> Script {
        let mut builder = Builder::new();
        for token in self.0 {
            builder = match token {
                Token::Push(value) => builder.push_int(value as i64),
                Token::Op(opcode) => builder.push_opcode(opcode),
            };
        }
        Script::new(name).push_script(builder.into_script())
    }
}

fn push(value: i32) -> Program {
    Program(vec![Token::Push(value)])
}

fn op(opcode: Opcode) -> Program {
    Program(vec![Token::Op(opcode)])
}

fn script_num_push_cost(value: i32) -> usize {
    if value == 0 || value == -1 || (1..=16).contains(&value) {
        return 1;
    }
    let mut value = value.unsigned_abs();
    let mut bytes = 0;
    let mut last = 0;
    while value > 0 {
        last = value & 0xff;
        bytes += 1;
        value /= 256;
    }
    if last & 0x80 != 0 {
        bytes += 1;
    }
    1 + bytes
}

#[derive(Clone)]
struct PushStep {
    from: usize,
    emit: Program,
}

fn optimize_push_sequence(values: &[i32]) -> Program {
    fn update(
        dp: &mut [usize],
        previous: &mut [Option<PushStep>],
        to: usize,
        cost: usize,
        from: usize,
        emit: Program,
    ) {
        if cost < dp[to] {
            dp[to] = cost;
            previous[to] = Some(PushStep { from, emit });
        }
    }

    let mut dp = vec![usize::MAX; values.len() + 1];
    let mut previous = vec![None; values.len() + 1];
    dp[0] = 0;

    for i in 0..values.len() {
        let base = dp[i];
        update(
            &mut dp,
            &mut previous,
            i + 1,
            base + script_num_push_cost(values[i]),
            i,
            push(values[i]),
        );
        if i >= 1 && values[i] == values[i - 1] {
            update(&mut dp, &mut previous, i + 1, base + 1, i, op(OP_DUP));
        }
        if i >= 2 && values[i] == values[i - 2] {
            update(&mut dp, &mut previous, i + 1, base + 1, i, op(OP_OVER));
        }
        for depth in 2..=16 {
            if depth < i && values[i] == values[i - 1 - depth] {
                let mut emit = push(depth as i32);
                emit.op(OP_PICK);
                update(
                    &mut dp,
                    &mut previous,
                    i + 1,
                    base + script_num_push_cost(depth as i32) + 1,
                    i,
                    emit,
                );
            }
        }
        if i >= 2
            && i + 2 <= values.len()
            && values[i] == values[i - 2]
            && values[i + 1] == values[i - 1]
        {
            update(&mut dp, &mut previous, i + 2, base + 1, i, op(OP_2DUP));
        }
        if i >= 3
            && i + 3 <= values.len()
            && values[i] == values[i - 3]
            && values[i + 1] == values[i - 2]
            && values[i + 2] == values[i - 1]
        {
            update(&mut dp, &mut previous, i + 3, base + 1, i, op(OP_3DUP));
        }
        if i >= 4
            && i + 2 <= values.len()
            && values[i] == values[i - 4]
            && values[i + 1] == values[i - 3]
        {
            update(&mut dp, &mut previous, i + 2, base + 1, i, op(OP_2OVER));
        }
    }

    let mut chunks = Vec::new();
    let mut i = values.len();
    while i > 0 {
        let step = previous[i]
            .clone()
            .unwrap_or_else(|| panic!("AES table push optimizer failed at {i}"));
        i = step.from;
        chunks.push(step.emit);
    }
    chunks.reverse();
    let mut out = Program::default();
    for chunk in chunks {
        out.extend(chunk);
    }
    out
}

fn table_pushes() -> Program {
    let xtime_bias_low: [i32; 16] = std::array::from_fn(|high| if high & 8 != 0 { 0xb } else { 0 });
    let xtime_double_low: [i32; 16] = std::array::from_fn(|low| ((low << 1) & 0xf) as i32);
    let xtime_high: [i32; 16] = std::array::from_fn(|high| {
        ((((high << 1) & 0xf) ^ usize::from(high & 8 != 0)) & 0xf) as i32
    });
    let xor_shift: [i32; 16] = std::array::from_fn(|row| XOR_ADDR + 16 * row as i32);

    let mut values = Vec::with_capacity(TABLE_ITEMS);
    values.extend(SBOX.iter().rev().map(|byte| i32::from(byte & 0xf)));
    values.extend(SBOX.iter().rev().map(|byte| i32::from(byte >> 4)));
    values.extend(
        (0..256)
            .rev()
            .map(|index| ((index / 16) ^ (index % 16)) as i32),
    );
    values.extend(xtime_bias_low.into_iter().rev());
    values.extend(xtime_double_low.into_iter().rev());
    values.extend(xtime_high.into_iter().rev());
    values.extend(xor_shift.into_iter().rev());
    assert_eq!(values.len(), TABLE_ITEMS);
    optimize_push_sequence(&values)
}

struct AesScript {
    round_keys: [[u8; 16]; 11],
}

impl AesScript {
    fn lookup(address: i32, scratch_below: usize) -> Program {
        let mut out = push(address + scratch_below as i32);
        out.op(OP_ADD);
        out.op(OP_PICK);
        out
    }

    fn copy_state(nibble: usize, scratch: usize) -> Program {
        let mut out = push((nibble + scratch) as i32);
        out.op(OP_PICK);
        out
    }

    fn copy_scratch(depth: usize) -> Program {
        match depth {
            0 => op(OP_DUP),
            1 => op(OP_OVER),
            _ => {
                let mut out = push(depth as i32);
                out.op(OP_PICK);
                out
            }
        }
    }

    /// XOR the top two nibbles, preserving `scratch_below` items beneath them.
    fn xor_top_two(scratch_below: usize) -> Program {
        let mut out = Self::lookup(XOR_SHIFT_ADDR, scratch_below + 1);
        out.op(OP_ADD);
        if scratch_below != 0 {
            out.push(scratch_below as i32);
            out.op(OP_ADD);
        }
        out.op(OP_PICK);
        out
    }

    fn xor_constant(constant: u8, scratch_below: usize) -> Program {
        if constant == 0 {
            return Program::default();
        }
        Self::lookup(XOR_ADDR + 16 * i32::from(constant), scratch_below)
    }

    fn finish_state_transform(out: &mut Program) {
        for _ in 0..STATE_NIBBLES / 2 {
            out.op(OP_2DROP);
        }
        for _ in 0..STATE_NIBBLES {
            out.op(OP_FROMALTSTACK);
        }
    }

    fn initialize_tables() -> Program {
        let mut out = Program::default();
        for _ in 0..STATE_NIBBLES {
            out.op(OP_TOALTSTACK);
        }
        out.extend(table_pushes());
        for _ in 0..STATE_NIBBLES {
            out.op(OP_FROMALTSTACK);
        }
        out
    }

    /// Fused AddRoundKey(input) + SubBytes + ShiftRows + AddRoundKey(output).
    /// Only the first invocation has an input key and only the final one has
    /// an output key.
    fn sub_shift(&self, input_key: Option<usize>, output_key: Option<usize>) -> Program {
        let input_key = input_key.map(|round| bytes_to_nibbles(self.round_keys[round]));
        let output_key = output_key.map(|round| bytes_to_nibbles(self.round_keys[round]));
        let mut out = Program::default();

        for destination in 0..BLOCK_BYTES {
            let source = SHIFT_ROWS[destination];
            out.extend(Self::copy_state(2 * source, 0));
            if let Some(key) = &input_key {
                out.extend(Self::xor_constant(key[2 * source], 0));
            }
            out.extend(Self::copy_state(2 * source + 1, 1));
            if let Some(key) = &input_key {
                out.extend(Self::xor_constant(key[2 * source + 1], 1));
            }
            out.op(OP_SWAP);

            // Convert (high, low) to the absolute XOR-table row pointer
            // XOR_ADDR + 16*high + low using the shared shift table.
            out.extend(Self::lookup(XOR_SHIFT_ADDR, 1));
            out.op(OP_ADD);
            out.op(OP_DUP);

            // One encoded byte index now addresses both S-box nibble tables.
            out.push(XOR_ADDR - (SBOX_HI_ADDR + 1));
            out.op(OP_SUB);
            out.op(OP_PICK);
            if let Some(key) = &output_key {
                out.extend(Self::xor_constant(key[2 * destination], 1));
            }
            out.op(OP_TOALTSTACK);

            out.push(XOR_ADDR - SBOX_LO_ADDR);
            out.op(OP_SUB);
            out.op(OP_PICK);
            if let Some(key) = &output_key {
                out.extend(Self::xor_constant(key[2 * destination + 1], 0));
            }
            out.op(OP_TOALTSTACK);
        }

        Self::finish_state_transform(&mut out);
        out
    }

    fn xtime_high(byte: usize, scratch_below: usize) -> Program {
        let mut out = Self::copy_state(2 * byte, scratch_below);
        out.extend(Self::lookup(XTIME_HI_ADDR, scratch_below));
        out.extend(Self::copy_state(2 * byte + 1, scratch_below + 1));
        out.push(7);
        out.op(OP_GREATERTHAN);
        out.extend(Self::xor_top_two(scratch_below));
        out
    }

    fn xtime_low(byte: usize, scratch_below: usize) -> Program {
        let mut out = Self::copy_state(2 * byte + 1, scratch_below);
        out.extend(Self::lookup(XTIME_DOUBLE_LO_ADDR, scratch_below));
        out.extend(Self::copy_state(2 * byte, scratch_below + 1));
        out.extend(Self::lookup(XTIME_BIAS_LO_ADDR, scratch_below + 1));
        out.extend(Self::xor_top_two(scratch_below));
        out
    }

    fn mix_output_from_xtimes(
        &self,
        column: usize,
        row: usize,
        high: bool,
        key_nibble: u8,
    ) -> Program {
        let byte = |row: usize| 4 * column + (row & 3);
        let current = byte(row);
        let next = byte(row + 1);
        let nibble = |byte: usize| 2 * byte + usize::from(!high);

        // Four bytes' high/low xtime results are cached above the state as
        // [lo3, hi3, ..., lo0, hi0, t_lo, t_hi], where t = a^b^c^d. Each
        // xtime value is reused by two outputs and t by all four.
        let xtime_depth = |byte: usize, high: bool| {
            let row = byte & 3;
            2 * (3 - row) + usize::from(high)
        };
        let mut out = Self::copy_scratch(xtime_depth(current, high));
        out.extend(Self::copy_scratch(xtime_depth(next, high) + 1));
        out.extend(Self::xor_top_two(10));
        out.extend(Self::copy_state(nibble(current), 11));
        out.extend(Self::xor_top_two(10));
        out.extend(Self::copy_scratch(if high { 10 } else { 9 }));
        out.extend(Self::xor_top_two(10));
        out.extend(Self::xor_constant(key_nibble, 10));
        out
    }

    /// Fused MixColumns + AddRoundKey for a full AES round.
    fn mix_columns_add_key(&self, round: usize) -> Program {
        let key = bytes_to_nibbles(self.round_keys[round]);
        let mut out = Program::default();
        for column in 0..4 {
            // t = a ^ b ^ c ^ d, once for each nibble.
            for high in [true, false] {
                for row in 0..4 {
                    let byte = 4 * column + row;
                    out.extend(Self::copy_state(
                        2 * byte + usize::from(!high),
                        usize::from(!high) + usize::from(row != 0),
                    ));
                    if row != 0 {
                        out.extend(Self::xor_top_two(usize::from(!high)));
                    }
                }
            }

            // Cache xtime(byte) once per input byte. The AES matrix uses each
            // value in two adjacent output rows.
            for row in 0..4 {
                let byte = 4 * column + row;
                out.extend(Self::xtime_high(byte, 2 + 2 * row));
                out.extend(Self::xtime_low(byte, 3 + 2 * row));
            }
            for row in 0..4 {
                let byte = 4 * column + row;
                out.extend(self.mix_output_from_xtimes(column, row, true, key[2 * byte]));
                out.op(OP_TOALTSTACK);
                out.extend(self.mix_output_from_xtimes(column, row, false, key[2 * byte + 1]));
                out.op(OP_TOALTSTACK);
            }
            for _ in 0..5 {
                out.op(OP_2DROP);
            }
        }
        Self::finish_state_transform(&mut out);
        out
    }

    fn generate(self) -> Program {
        let mut out = Self::initialize_tables();
        out.extend(self.sub_shift(Some(0), None));
        out.extend(self.mix_columns_add_key(1));
        for round in 2..10 {
            out.extend(self.sub_shift(None, None));
            out.extend(self.mix_columns_add_key(round));
        }
        out.extend(self.sub_shift(None, Some(10)));

        for _ in 0..STATE_NIBBLES {
            out.op(OP_TOALTSTACK);
        }
        for _ in 0..TABLE_ITEMS / 2 {
            out.op(OP_2DROP);
        }
        for _ in 0..STATE_NIBBLES {
            out.op(OP_FROMALTSTACK);
        }
        out
    }
}

/// AES-128 encryption with a generation-time key.
///
/// Input and output are 32 canonical nibbles. Byte 0's high nibble is on top;
/// byte 15's low nibble is deepest.
pub fn aes128_encrypt(key: [u8; 16]) -> Script {
    AesScript {
        round_keys: aes128_expand_key(key),
    }
    .generate()
    .into_script("AES-128 encryption")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::{
        execution::execute_script,
        script::{script, ScriptCompilation},
    };

    fn execute_vector(key: [u8; 16], plaintext: [u8; 16], ciphertext: [u8; 16]) -> usize {
        let plaintext = bytes_to_nibbles(plaintext);
        let ciphertext = bytes_to_nibbles(ciphertext);
        let result = execute_script(script! {
            for i in (0..STATE_NIBBLES).rev() {
                { plaintext[i] as u32 }
            }
            { aes128_encrypt(key) }
            for expected in ciphertext {
                { expected as u32 }
                OP_EQUALVERIFY
            }
            OP_TRUE
        });
        assert!(result.success, "AES-128 Script failed: {result}");
        result.stats.max_nb_stack_items
    }

    #[test]
    fn reference_vectors() {
        let vectors = [
            (
                [
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                    0x0d, 0x0e, 0x0f,
                ],
                [
                    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                    0xdd, 0xee, 0xff,
                ],
                [
                    0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70,
                    0xb4, 0xc5, 0x5a,
                ],
            ),
            (
                [0; 16],
                [0; 16],
                [
                    0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca,
                    0x34, 0x2b, 0x2e,
                ],
            ),
            (
                [
                    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09,
                    0xcf, 0x4f, 0x3c,
                ],
                [
                    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73,
                    0x93, 0x17, 0x2a,
                ],
                [
                    0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24,
                    0x66, 0xef, 0x97,
                ],
            ),
        ];

        for (key, plaintext, expected) in vectors {
            assert_eq!(aes128_encrypt_ref(key, plaintext), expected);
        }
    }

    #[test]
    fn script_vectors_and_metrics() {
        let key = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let plaintext = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let ciphertext = aes128_encrypt_ref(key, plaintext);
        let max_stack = execute_vector(key, plaintext, ciphertext);
        let size = aes128_encrypt(key).compile_with_policy().len();
        let zero_key_size = aes128_encrypt([0; 16]).compile_with_policy().len();
        let zero_stack = execute_vector(
            [0; 16],
            [0; 16],
            [
                0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34,
                0x2b, 0x2e,
            ],
        );
        eprintln!(
            "AES-128 script size: {size} bytes ({zero_key_size} with zero key); max stack: {max_stack}/{zero_stack}"
        );
        assert_eq!(zero_key_size, 25_388);
        assert_eq!(max_stack, 908);
        assert_eq!(zero_stack, 908);
    }
}
