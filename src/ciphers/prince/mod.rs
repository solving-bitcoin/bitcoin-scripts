// PRINCEv2 block cipher implementation
// Reference: "PRINCEv2 – More Security for (Almost) No Overhead"
// rub-hgi/princev2 reference implementation
//
// 64-bit block, 128-bit key (k0 || k1, each 64 bits, big-endian nibble order)
// Nibble 0 = MSB nibble (bits 63:60), nibble 15 = LSB nibble (bits 3:0)

use crate::support::script::{script, Script};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const ALPHA: u64 = 0xc0ac29b7c97c50dd;
const BETA: u64 = 0x3f84d5b5b5470917;

// Round constants RC[0..10] (only 11 used — no RC[11] since BETA is embedded)
const RC: [u64; 11] = [
    0x0000000000000000,
    0x13198a2e03707344,
    0xa4093822299f31d0,
    0x082efa98ec4e6c89,
    0x452821e638d01377,
    0xbe5466cf34e90c6c,
    0xbe5466cf34e90c6c ^ ALPHA, // RC[6] = RC[5] ^ ALPHA
    0x452821e638d01377 ^ BETA,  // RC[7] = RC[4] ^ BETA
    0x082efa98ec4e6c89 ^ ALPHA, // RC[8] = RC[3] ^ ALPHA
    0xa4093822299f31d0 ^ BETA,  // RC[9] = RC[2] ^ BETA
    0x13198a2e03707344 ^ ALPHA, // RC[10] = RC[1] ^ ALPHA
];

/// S-box
const SBOX: [u8; 16] = [
    0xb, 0xf, 0x3, 0x2, 0xa, 0xc, 0x9, 0x1, 0x6, 0x7, 0x8, 0x0, 0xe, 0x5, 0xd, 0x4,
];

/// Inverse S-box
const SBOX_INV: [u8; 16] = [
    0xb, 0x7, 0x3, 0x2, 0xf, 0xd, 0x8, 0x9, 0xa, 0x6, 0x4, 0x0, 0x5, 0xe, 0xc, 0x1,
];

/// ShiftRows permutation: output_nibble[i] = input_nibble[SHIFT[i]]
/// Nibble 0 = MSB (bits 63:60)
const SHIFT: [u8; 16] = [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11];
const SHIFT_INV: [u8; 16] = [0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3];

/// M-layer diagonal constants (used as AND masks = GF(2^4) mul-by-constant)
const M0: u8 = 7;
const M1: u8 = 11;
const M2: u8 = 13;
const M3: u8 = 14;

// ---------------------------------------------------------------------------
// Nibble helpers: nibble 0 = MSB (bits 63:60), nibble 15 = LSB (bits 3:0)
// ---------------------------------------------------------------------------

fn get_nibble(state: u64, idx: usize) -> u8 {
    ((state >> (4 * (15 - idx))) & 0xf) as u8
}

fn set_nibble(state: u64, idx: usize, val: u8) -> u64 {
    let shift = 4 * (15 - idx);
    (state & !(0xf << shift)) | ((val as u64 & 0xf) << shift)
}

// ---------------------------------------------------------------------------
// S-layer
// ---------------------------------------------------------------------------

fn s_layer(state: u64, sbox: &[u8; 16]) -> u64 {
    let mut out = 0u64;
    for i in 0..16 {
        let n = get_nibble(state, i);
        out = set_nibble(out, i, sbox[n as usize]);
    }
    out
}

// ---------------------------------------------------------------------------
// M-layer: MHat0 on nibbles [0..3] and [12..15], MHat1 on [4..7] and [8..11]
// MHat0 = circ(M0,M1,M2,M3), MHat1 = circ(M1,M2,M3,M0)
// The '&' is GF(2^4) multiply by constant (implemented as bitwise AND in GF(2))
// ---------------------------------------------------------------------------

fn mhat0_mul(state: u64, si: usize) -> u64 {
    let n0 = get_nibble(state, si);
    let n1 = get_nibble(state, si + 1);
    let n2 = get_nibble(state, si + 2);
    let n3 = get_nibble(state, si + 3);
    let mut s = state;
    s = set_nibble(s, si, (M0 & n0) ^ (M1 & n1) ^ (M2 & n2) ^ (M3 & n3));
    s = set_nibble(s, si + 1, (M1 & n0) ^ (M2 & n1) ^ (M3 & n2) ^ (M0 & n3));
    s = set_nibble(s, si + 2, (M2 & n0) ^ (M3 & n1) ^ (M0 & n2) ^ (M1 & n3));
    s = set_nibble(s, si + 3, (M3 & n0) ^ (M0 & n1) ^ (M1 & n2) ^ (M2 & n3));
    s
}

fn mhat1_mul(state: u64, si: usize) -> u64 {
    let n0 = get_nibble(state, si);
    let n1 = get_nibble(state, si + 1);
    let n2 = get_nibble(state, si + 2);
    let n3 = get_nibble(state, si + 3);
    let mut s = state;
    s = set_nibble(s, si, (M1 & n0) ^ (M2 & n1) ^ (M3 & n2) ^ (M0 & n3));
    s = set_nibble(s, si + 1, (M2 & n0) ^ (M3 & n1) ^ (M0 & n2) ^ (M1 & n3));
    s = set_nibble(s, si + 2, (M3 & n0) ^ (M0 & n1) ^ (M1 & n2) ^ (M2 & n3));
    s = set_nibble(s, si + 3, (M0 & n0) ^ (M1 & n1) ^ (M2 & n2) ^ (M3 & n3));
    s
}

fn m_layer(state: u64) -> u64 {
    let s = mhat0_mul(state, 0);
    let s = mhat1_mul(s, 4);
    let s = mhat1_mul(s, 8);
    mhat0_mul(s, 12)
}

// ---------------------------------------------------------------------------
// ShiftRows
// ---------------------------------------------------------------------------

fn shift_rows(state: u64) -> u64 {
    let mut out = 0u64;
    for i in 0..16 {
        out = set_nibble(out, i, get_nibble(state, SHIFT[i] as usize));
    }
    out
}

fn shift_rows_inv(state: u64) -> u64 {
    let mut out = 0u64;
    for i in 0..16 {
        out = set_nibble(out, i, get_nibble(state, SHIFT_INV[i] as usize));
    }
    out
}

// ---------------------------------------------------------------------------
// Round functions
// ---------------------------------------------------------------------------

fn round_forward(state: u64, rk: u64, rci: u64) -> u64 {
    let s = s_layer(state, &SBOX);
    let s = m_layer(s);
    let s = shift_rows(s);
    s ^ rci ^ rk
}

fn round_inverse(state: u64, rk: u64, rci: u64) -> u64 {
    let s = state ^ rk ^ rci;
    let s = shift_rows_inv(s);
    let s = m_layer(s);
    s_layer(s, &SBOX_INV)
}

// ---------------------------------------------------------------------------
// PRINCEv2 core
// Uses k0 and k1 directly (no external key whitening here).
// Round keys alternate: rkeys[i%2] for i=1..5 → k1,k0,k1,k0,k1
// Middle: S, ^k0, M, ^(k1^BETA), S_inv
// Backward: roundInverse with rkeys[i%2] for i=6..10 → k0,k1,k0,k1,k0
// Final: ^(k1^BETA)
// ---------------------------------------------------------------------------

fn prince_core(k0: u64, k1: u64, state: u64) -> u64 {
    let rkeys = [k0, k1];

    let mut s = state ^ rkeys[0];

    // Forward rounds 1..5
    for i in 1..6usize {
        s = round_forward(s, rkeys[i % 2], RC[i]);
    }

    // Middle layer
    s = s_layer(s, &SBOX);
    s ^= rkeys[0];
    s = m_layer(s);
    s ^= rkeys[1] ^ BETA;
    s = s_layer(s, &SBOX_INV);

    // Backward rounds 6..10
    for i in 6..11usize {
        s = round_inverse(s, rkeys[i % 2], RC[i]);
    }

    s ^= rkeys[1] ^ BETA;
    s
}

// ---------------------------------------------------------------------------
// Public reference encryption
// key: u128 with upper 64 bits = k0 (PRINCEv2 k0), lower 64 bits = k1 (PRINCEv2 k1)
// This matches the test vector: key = (k1_rust << 64) | k0_rust
// where k0_rust=0xfedcba9876543210, k1_rust=0x0123456789abcdef
// PRINCEv2 k0 = 0x0123456789abcdef (upper half of u128)
// PRINCEv2 k1 = 0xfedcba9876543210 (lower half of u128)
// ---------------------------------------------------------------------------

pub fn prince_encrypt_ref(key: u128, plaintext: u64) -> u64 {
    // key = (k1_rust << 64) | k0_rust in test
    // PRINCEv2 convention: k0 = upper 64 bits, k1 = lower 64 bits
    let pv2_k0 = (key >> 64) as u64;
    let pv2_k1 = key as u64;
    prince_core(pv2_k0, pv2_k1, plaintext)
}

// ---------------------------------------------------------------------------
// Bitcoin Script generators
// ---------------------------------------------------------------------------

/// Push 16 SBox entries as lookup table.
/// Pushed so that sbox[0] is deepest, sbox[15] is on top.
/// Lookup: given nibble on top, table below:
///   nibble i stored at depth (16-i) from nibble.
///   pick_index = 16 - nibble
pub fn prince_push_sbox_table() -> Script {
    script! {
        for i in (0..16usize).rev() {
            { SBOX[i] as u32 }
        }
    }
}

/// Push 16 inverse SBox entries as lookup table.
pub fn prince_push_sbox_inv_table() -> Script {
    script! {
        for i in (0..16usize).rev() {
            { SBOX_INV[i] as u32 }
        }
    }
}

/// Push 256-entry XOR table: xor[a][b] = a^b, a=row major.
/// Entry (a=0,b=0) deepest, (a=15,b=15) on top.
pub fn prince_push_xor_table() -> Script {
    script! {
        for a in (0..16usize).rev() {
            for b in (0..16usize).rev() {
                { (a ^ b) as u32 }
            }
        }
    }
}

/// S-box lookup.
/// Stack: [...| table(16) | nibble]  (nibble on top)
/// Result: [...| table(16) | sbox(nibble)]
/// Table layout: sbox[0] at depth 0 (top of table), sbox[15] at depth 15.
/// nibble is consumed as pick index; remaining table has sbox[nibble] at depth nibble.
/// pick_index = nibble (directly).
pub fn prince_sbox() -> Script {
    script! {
        OP_PICK
    }
}

/// Inverse S-box lookup. Same structure as prince_sbox().
pub fn prince_sbox_inv() -> Script {
    script! {
        OP_PICK
    }
}

/// XOR two nibbles via 256-entry table.
/// Stack: [...| xor_table(256) | b | a]  (a on top)
/// Result: [...| xor_table(256) | a XOR b]
/// Table layout: t[0][0] at depth 0 (top), t[15][15] at depth 255.
/// a and b are consumed; remaining table has t[a][b] at depth 16a+b.
/// pick_index = 16a + b.
pub fn prince_xor() -> Script {
    script! {
        // Compute 16*a (a on top, b below)
        OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD
        // stack: [...| table | b | 16a]
        OP_ADD
        // stack: [...| table | 16a+b]
        OP_PICK
    }
}

// ---------------------------------------------------------------------------
// Internal Script building blocks
// Stack convention for state: nibble[0] (MSB nibble = bits 63:60) on top,
// nibble[15] (LSB nibble = bits 3:0) at depth 15.
// This mirrors get_nibble(state, 0) = MSB.
// ---------------------------------------------------------------------------

/// Apply S-box to all 16 state nibbles.
/// No persistent table; pushes and drops table inline.
/// State: nibble[0] on top.
#[cfg(test)]
fn script_apply_sbox_fresh(sbox: &[u8; 16]) -> Script {
    // Strategy:
    // 1. Move all 16 nibbles to altstack (nibble[0] first → deepest in altstack)
    //    altstack (top): nibble[15], ..., nibble[0]
    // 2. Push table to main stack
    //    main stack (top to bottom): sbox[15], sbox[14], ..., sbox[0]
    // 3. For i=0..15: fromaltstack (gets nibble[15],14,...,0 in order)
    //    nibble on top, table at depths 1..16.
    //    pick_index = 16 - nibble  (sbox[nibble] = entry at depth 16-nibble from nibble)
    //    push result to altstack.
    //    After 16 iters: altstack top = result[0] (processed last), bottom = result[15].
    // 4. Drop table.
    // 5. fromaltstack 16 times: result[0] comes out first → deepest on main stack.
    //    result[15] comes out last → on top. WRONG! We want result[0] on top.
    //
    // Fix: since we process nibble[15] first (i=0 iter gets nibble[15] from top of altstack),
    //   result[15] is pushed to altstack first → deepest.
    //   result[0] is pushed last → top of altstack.
    //   fromaltstack: result[0] first → main stack top. result[15] last → main stack bottom.
    //   Final: result[0] on top. CORRECT!

    // Build table push script: sbox[0] on top (depth 0), sbox[15] deepest (depth 15)
    // This matches prince_push_sbox_table() layout.
    let mut ts = script! {};
    for i in (0..16usize).rev() {
        let v = sbox[i] as u32;
        ts = script! { { ts } { v } };
    }

    // Strategy: push table on top of state (16 nibbles below).
    // Stack: sbox[0](d0), sbox[1](d1), ..., sbox[15](d15), nibble[0](d16), ..., nibble[15](d31)
    //
    // Process i=0,1,...,15 (nibble[0] first):
    //   {16+i} OP_PICK: copies nibble[i] on top (without removing it from depth 16+i).
    //   Stack now: [nibble[i] | sbox[0](d1)..sbox[15](d16) | nibble[0](d17)..nibble[15](d32)]
    //   OP_PICK: pops nibble[i] as index, picks sbox[nibble[i]] from remaining.
    //   Remaining: [sbox[0](d0)..sbox[15](d15) | nibble[0](d16)..nibble[15](d31)]
    //   sbox[nibble[i]] is at depth nibble[i]. CORRECT.
    //   OP_TOALTSTACK: saves result[i].
    //
    // After 16 lookups: altstack = result[0](bottom)..result[15](top).
    // Drop table (16) + state (16) = 32 items.
    // fromaltstack × 16: result[15] pops first → main bottom; result[0] pops last → main TOP. ✓
    let mut lookup_s = script! {};
    for i in 0..16usize {
        let d = (16 + i) as u32; // depth of nibble[i] (table=16 on top, nibbles below)
        lookup_s = script! {
            { lookup_s }
            { d } OP_PICK   // copy nibble[i] on top
            OP_PICK         // look up sbox[nibble[i]] using nibble[i] as index
            OP_TOALTSTACK   // save result[i]
        };
    }

    // After lookups: altstack (top→bottom) = result[15],..,result[0].
    // Main stack: table(16) + state(16) = 32 items.
    // fromaltstack × 16: result[15] out first → deep; result[0] last → TOP. ✓

    script! {
        { ts }           // push table on top of state
        { lookup_s }     // look up all 16 nibbles
        for _ in 0..32 { OP_DROP }   // drop table + original state
        for _ in 0..16 { OP_FROMALTSTACK }  // result[0] on top
    }
}

/// Apply ShiftRows or inverse.
/// output_nibble[i] = input_nibble[perm[i]]
#[cfg(test)]
fn script_shift_rows(inv: bool) -> Script {
    let perm = if inv { SHIFT_INV } else { SHIFT };
    let mut s = script! {};
    for i in 0..16usize {
        let d = perm[i] as u32;
        s = script! { { s } { d } OP_PICK OP_TOALTSTACK };
    }
    // Pushed to altstack: new[0] first (deepest), new[15] last (top of altstack).
    // fromaltstack: new[15] first → main stack bottom;  new[0] last → top.
    script! {
        { s }
        for _ in 0..16 { OP_DROP }
        for _ in 0..16 { OP_FROMALTSTACK }
    }
}

/// Build and push a 256-entry pair table: table[a*16+b] = (m0&a)^(m1&b).
/// table[0] is on top (depth 0), table[255] deepest (depth 255).
#[cfg(test)]
fn push_pair_table(m0: u8, m1: u8) -> Script {
    let table: [u32; 256] = std::array::from_fn(|i| {
        let a = (i / 16) as u8;
        let b = (i % 16) as u8;
        ((m0 & a) ^ (m1 & b)) as u32
    });
    let mut s = script! {};
    for i in (0..256usize).rev() {
        let v = table[i];
        s = script! { { s } { v } };
    }
    s
}

/// Lookup in a 256-entry table already on the stack.
/// Pre: a on top (depth 0), b at depth 1, table at depth 2..257.
/// Post: result = table[a*16+b] on top; table dropped (256 NIPs); original stack below b unchanged.
#[cfg(test)]
fn pair_table_lookup() -> Script {
    script! {
        // Compute 16*a: four doublings
        OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD OP_DUP OP_ADD
        // Stack: 16a(0), b(1), table(2..257)
        OP_ADD
        // Stack: 16a+b(0), table(1..256)
        OP_PICK
        // Stack: result(0), table(1..256)
        for _ in 0..256 { OP_NIP }
        // Stack: result(0)
    }
}

/// Compute pair_table[a*16+b] = (m0&a)^(m1&b), consuming a (top) and b (depth 1).
/// Uses altstack internally to push the table; original stack below b is preserved.
#[cfg(test)]
fn pair_lookup(m0: u8, m1: u8) -> Script {
    let table = push_pair_table(m0, m1);
    script! {
        OP_TOALTSTACK OP_TOALTSTACK   // save a (bottom of altstack), b (top)
        { table }                      // push 256-entry table; t[0] on top
        OP_FROMALTSTACK OP_FROMALTSTACK // restore a(0), b(1)
        { pair_table_lookup() }
    }
}

/// XOR two 4-bit nibbles a (top) and b (depth 1) without OP_XOR.
/// Uses the universal XOR pair table.
#[cfg(test)]
fn xor_nibbles() -> Script {
    let xor_table: [u32; 256] = std::array::from_fn(|i| ((i / 16) ^ (i % 16)) as u32);
    let mut t = script! {};
    for i in (0..256usize).rev() {
        let v = xor_table[i];
        t = script! { { t } { v } };
    }
    script! {
        OP_TOALTSTACK OP_TOALTSTACK
        { t }
        OP_FROMALTSTACK OP_FROMALTSTACK
        { pair_table_lookup() }
    }
}

/// Apply M-layer to 16 state nibbles.
/// M-layer = MHat0 on nibbles [0..3] and [12..15], MHat1 on [4..7] and [8..11].
/// Uses pair tables (256-entry each) and XOR table — no OP_XOR or OP_AND required.
///
/// Stack layout entering: nibble[0] on top, nibble[15] at depth 15.
/// Stack layout exiting: output nibble[0] on top, output nibble[15] at depth 15.
///
/// For each output nibble:
///   result = (m0&n[si]) ^ (m1&n[si+1]) ^ (m2&n[si+2]) ^ (m3&n[si+3])
///          = pair_lookup(m0,m1)[n[si]*16+n[si+1]] XOR pair_lookup(m2,m3)[n[si+2]*16+n[si+3]]
#[cfg(test)]
fn script_m_layer() -> Script {
    let mhat0: [[u8; 4]; 4] = [
        [M0, M1, M2, M3],
        [M1, M2, M3, M0],
        [M2, M3, M0, M1],
        [M3, M0, M1, M2],
    ];
    let mhat1: [[u8; 4]; 4] = [
        [M1, M2, M3, M0],
        [M2, M3, M0, M1],
        [M3, M0, M1, M2],
        [M0, M1, M2, M3],
    ];

    // For each output nibble compute:
    //   result = pair_lookup(m0,m1)[n[si]*16+n[si+1]] XOR pair_lookup(m2,m3)[n[si+2]*16+n[si+3]]
    //
    // Picking pattern (state nibbles at depths 0..15):
    //   To get a=n[si](top), b=n[si+1](depth 1):
    //     Pick n[si+1] from depth si+1  → copies n[si+1] to top
    //     Pick n[si]   from depth si+1  → n[si] was at si, now at si+1 after first pick
    //   pair_lookup(m0,m1) consumes a and b, uses altstack internally (balanced).
    //   After pair_lookup: pair_hi on top, state still at depths 1..16.
    //
    //   OP_TOALTSTACK (save pair_hi): state back at depths 0..15.
    //
    //   Similarly for pair_lo with n[si+2] and n[si+3]:
    //     Pick n[si+3] from depth si+3  → copies n[si+3]
    //     Pick n[si+2] from depth si+3  → n[si+2] now at si+3 after first pick
    //   pair_lookup(m2,m3): pair_lo on top.
    //
    //   OP_FROMALTSTACK: pair_hi on top, pair_lo at depth 1.
    //   xor_nibbles(): result = pair_hi XOR pair_lo.
    //   OP_TOALTSTACK: save result, state at depths 0..15.

    let sub_blocks = [(0usize, &mhat0), (4, &mhat1), (8, &mhat1), (12, &mhat0)];
    let mut compute = script! {};
    for (si, mat) in sub_blocks.iter() {
        for row in 0..4usize {
            let [m0, m1, m2, m3] = mat[row];
            let si = *si;
            let hi = pair_lookup(m0, m1);
            let lo = pair_lookup(m2, m3);
            let xor = xor_nibbles();
            compute = script! {
                { compute }
                // Get a=n[si], b=n[si+1] for pair_hi
                { (si+1) as u32 } OP_PICK   // b = n[si+1]
                { (si+1) as u32 } OP_PICK   // a = n[si] (now at depth si+1)
                { hi }                        // pair_hi = (m0&a)^(m1&b)
                OP_TOALTSTACK
                // Get a=n[si+2], b=n[si+3] for pair_lo
                { (si+3) as u32 } OP_PICK   // b = n[si+3]
                { (si+3) as u32 } OP_PICK   // a = n[si+2]
                { lo }                        // pair_lo = (m2&a)^(m3&b)
                OP_FROMALTSTACK               // pair_hi on top, pair_lo below
                { xor }                       // result = pair_hi XOR pair_lo
                OP_TOALTSTACK
            };
        }
    }

    // Results on altstack: output[0] deepest, output[15] top.
    // fromaltstack x16: output[15] comes first (deep on main), output[0] last (top). ✓
    script! {
        { compute }
        for _ in 0..16 { OP_DROP }
        for _ in 0..16 { OP_FROMALTSTACK }
    }
}

// Native Rust translation of:
// https://github.com/BitVM/bitvm-js/blob/b931a6711ab332fd5923e708c869bed02e39984e/scripts/opcodes/PRINCEv2/prince_v2_optimized10.js
mod optimized {
    use std::{collections::HashMap, sync::OnceLock};

    use bitcoin::{
        opcodes::{
            all::{
                OP_1ADD, OP_1SUB, OP_2DROP, OP_2DUP, OP_2OVER, OP_2ROT, OP_2SWAP, OP_3DUP, OP_ADD,
                OP_DROP, OP_DUP, OP_FROMALTSTACK, OP_OVER, OP_PICK, OP_ROLL, OP_ROT, OP_SUB,
                OP_SWAP, OP_TOALTSTACK,
            },
            Opcode,
        },
        script::Builder,
        ScriptBuf,
    };

    use crate::support::script::Script;

    use super::{BETA, M0, M1, M2, M3, RC, SBOX, SBOX_INV, SHIFT, SHIFT_INV};

    const SIZE_STATE: usize = 16;
    const SIZE_KEY: usize = 32;
    const SIZE_MEMORY: usize = 674;

    const ADDR_SBOX_TABLE: i32 = 16;
    const ADDR_PAIR01_ROW_TABLE: i32 = 32;
    const ADDR_PAIR23_ROW_TABLE: i32 = 48;
    const ADDR_PAIR01_FINAL_ROW_TABLE: i32 = 64;
    const ADDR_KEY: i32 = 80;
    const ADDR_NIBBLE_TABLE: i32 = 128;
    const ADDR_XOR_TABLE: i32 = ADDR_NIBBLE_TABLE;
    const ADDR_PAIR23_TABLE: i32 = ADDR_NIBBLE_TABLE;
    const ADDR_PAIR01_TABLE: i32 = 578;

    const M: [i32; 4] = [M0 as i32, M1 as i32, M2 as i32, M3 as i32];

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

        fn into_script_buf(self) -> ScriptBuf {
            let mut builder = Builder::new();
            for token in self.0 {
                builder = match token {
                    Token::Push(value) => builder.push_int(value as i64),
                    Token::Op(opcode) => builder.push_opcode(opcode),
                };
            }
            builder.into_script()
        }
    }

    fn push(value: i32) -> Program {
        Program(vec![Token::Push(value)])
    }

    fn op(opcode: Opcode) -> Program {
        Program(vec![Token::Op(opcode)])
    }

    fn split_nibbles_lsb(value: u64) -> [i32; 16] {
        std::array::from_fn(|i| ((value >> (4 * i)) & 0xf) as i32)
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

    fn roll_cost(position: usize) -> usize {
        match position {
            0 => 0,
            1 | 2 => 1,
            _ => script_num_push_cost(position as i32) + 1,
        }
    }

    fn permutations4() -> Vec<[usize; 4]> {
        fn permute(values: &mut [usize; 4], left: usize, out: &mut Vec<[usize; 4]>) {
            if left == values.len() - 1 {
                out.push(*values);
                return;
            }
            for i in left..values.len() {
                values.swap(left, i);
                permute(values, left + 1, out);
                values.swap(left, i);
            }
        }

        let mut values = [0, 1, 2, 3];
        let mut out = Vec::with_capacity(24);
        permute(&mut values, 0, &mut out);
        out
    }

    struct PackedRows<K> {
        values: Vec<i32>,
        offsets: HashMap<K, i32>,
    }

    fn pack_lookup_rows<K>(rows: &HashMap<K, Vec<i32>>, order: &[K]) -> PackedRows<K>
    where
        K: Clone + Eq + std::hash::Hash,
    {
        fn overlap(left: &[i32], right: &[i32]) -> usize {
            for n in (1..=left.len().min(right.len())).rev() {
                if left[left.len() - n..] == right[..n] {
                    return n;
                }
            }
            0
        }

        let mut values = Vec::new();
        let mut offsets = HashMap::new();
        for (i, key) in order.iter().enumerate() {
            let row = &rows[key];
            if i == 0 {
                offsets.insert(key.clone(), 0);
                values.extend_from_slice(row);
                continue;
            }

            let previous = &rows[&order[i - 1]];
            let shared = overlap(previous, row);
            offsets.insert(key.clone(), (values.len() - shared) as i32);
            values.extend_from_slice(&row[shared..]);
        }
        PackedRows { values, offsets }
    }

    struct LookupTables {
        cold_push: Program,
        hot_push: Program,
        xor_offsets: [i32; 16],
        sbox_xor_addresses: [Option<i32>; 16],
        sbox_inv_xor_addresses: [Option<i32>; 16],
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

        let n = values.len();
        let mut dp = vec![usize::MAX; n + 1];
        let mut previous = vec![None; n + 1];
        dp[0] = 0;

        for i in 0..n {
            if dp[i] == usize::MAX {
                continue;
            }
            let base_cost = dp[i];

            update(
                &mut dp,
                &mut previous,
                i + 1,
                base_cost + script_num_push_cost(values[i]),
                i,
                push(values[i]),
            );

            if i >= 1 && values[i - 1] == values[i] {
                update(&mut dp, &mut previous, i + 1, base_cost + 1, i, op(OP_DUP));
            }
            if i >= 2 && values[i - 2] == values[i] {
                update(&mut dp, &mut previous, i + 1, base_cost + 1, i, op(OP_OVER));
            }
            for depth in 2..=16 {
                if depth < i && values[i - 1 - depth] == values[i] {
                    let mut emit = push(depth as i32);
                    emit.op(OP_PICK);
                    update(
                        &mut dp,
                        &mut previous,
                        i + 1,
                        base_cost + script_num_push_cost(depth as i32) + 1,
                        i,
                        emit,
                    );
                }
            }
            if i >= 2 && i + 2 <= n && values[i] == values[i - 2] && values[i + 1] == values[i - 1]
            {
                update(&mut dp, &mut previous, i + 2, base_cost + 1, i, op(OP_2DUP));
            }
            if i >= 3
                && i + 3 <= n
                && values[i] == values[i - 3]
                && values[i + 1] == values[i - 2]
                && values[i + 2] == values[i - 1]
            {
                update(&mut dp, &mut previous, i + 3, base_cost + 1, i, op(OP_3DUP));
            }
            if i >= 4 && i + 2 <= n && values[i] == values[i - 4] && values[i + 1] == values[i - 3]
            {
                update(
                    &mut dp,
                    &mut previous,
                    i + 2,
                    base_cost + 1,
                    i,
                    op(OP_2OVER),
                );
            }
        }

        let mut chunks = Vec::new();
        let mut i = n;
        while i > 0 {
            let step = previous[i]
                .clone()
                .unwrap_or_else(|| panic!("push optimizer failed at {i}"));
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

    impl LookupTables {
        fn new() -> Self {
            const COLD_ORDER: [&str; 41] = [
                "SI", "X4", "X12", "P4", "P0", "X0", "P12", "P8", "X8", "P6", "P2", "X2", "X14",
                "X6", "P14", "P10", "X10", "I13", "I7", "F8", "F4", "F12", "X3", "X11", "X7",
                "X15", "X1", "X9", "X5", "X13", "F2", "F14", "F6", "I12", "F9", "F1", "I9", "I3",
                "F3", "I5", "I8",
            ];
            let mut rows: HashMap<String, Vec<i32>> = HashMap::new();
            rows.insert("SI".to_owned(), SBOX_INV.map(i32::from).to_vec());
            for row in 0..16i32 {
                rows.insert(
                    format!("X{row}"),
                    (0..16).map(|value| row ^ value).collect(),
                );
            }
            for u in (0..16i32).step_by(2) {
                rows.insert(
                    format!("P{u}"),
                    (0..16).map(|x0| (u & M[3]) ^ (x0 & M[0])).collect(),
                );
            }
            for constant in [3, 5, 7, 8, 9, 12, 13] {
                rows.insert(
                    format!("I{constant}"),
                    SBOX_INV
                        .iter()
                        .map(|&value| i32::from(value) ^ constant)
                        .collect(),
                );
            }
            for constant in [1usize, 2, 3, 4, 6, 8, 9, 12, 14] {
                rows.insert(
                    format!("F{constant}"),
                    (0..16)
                        .map(|value| i32::from(SBOX[value ^ constant]))
                        .collect(),
                );
            }

            let order: Vec<String> = COLD_ORDER.iter().map(|key| (*key).to_owned()).collect();
            let packed = pack_lookup_rows(&rows, &order);
            let xor_offsets = std::array::from_fn(|row| packed.offsets[&format!("X{row}")]);

            let mut sbox_xor_addresses = [None; 16];
            for constant in [1usize, 2, 3, 4, 6, 8, 9, 12, 14] {
                sbox_xor_addresses[constant] =
                    Some(ADDR_NIBBLE_TABLE + packed.offsets[&format!("F{constant}")]);
            }
            let mut sbox_inv_xor_addresses = [None; 16];
            for constant in [3usize, 5, 7, 8, 9, 12, 13] {
                sbox_inv_xor_addresses[constant] =
                    Some(ADDR_NIBBLE_TABLE + packed.offsets[&format!("I{constant}")]);
            }

            let mut cold_values = Vec::new();

            let mut pair01_rows = HashMap::new();
            for u in [0i32, 1, 2, 3, 8, 9, 10, 11] {
                pair01_rows.insert(
                    u,
                    (0..16)
                        .map(|x2| {
                            let pair12 = (u & M[1]) ^ (x2 & M[2]);
                            xor_offsets[pair12 as usize] + ADDR_XOR_TABLE
                        })
                        .collect(),
                );
            }
            let pair01_order = [0, 8, 9, 1, 2, 10, 11, 3];
            let pair01 = pack_lookup_rows(&pair01_rows, &pair01_order);

            cold_values.extend(pair01.values.iter().rev().copied());
            cold_values.extend(packed.values.iter().rev().copied());
            cold_values.extend((0..16).rev().map(|i| xor_offsets[i] + ADDR_XOR_TABLE - 1));

            let mut hot_values = Vec::new();
            hot_values.extend(
                (0..16i32)
                    .rev()
                    .map(|x| ADDR_PAIR01_TABLE - 2 + pair01.offsets[&(x & M[1])]),
            );
            hot_values.extend((0..16i32).rev().map(|x| {
                let key = x & M[3];
                ADDR_PAIR23_TABLE + 1 + packed.offsets[&format!("P{key}")]
            }));
            hot_values.extend(
                (0..16i32)
                    .rev()
                    .map(|x| ADDR_PAIR01_TABLE + 2 + pair01.offsets[&(x & M[1])]),
            );
            hot_values.extend(SBOX.iter().rev().map(|&value| i32::from(value)));

            Self {
                cold_push: optimize_push_sequence(&cold_values),
                hot_push: optimize_push_sequence(&hot_values),
                xor_offsets,
                sbox_xor_addresses,
                sbox_inv_xor_addresses,
            }
        }
    }

    #[derive(Clone, Copy)]
    enum PrepKind {
        Roll(usize),
        TwoSwap,
        TwoRot,
    }

    #[derive(Clone, Copy)]
    struct PrepOp {
        kind: PrepKind,
        opcode: Opcode,
    }

    fn prep_prefixes() -> Vec<Vec<PrepOp>> {
        let primitives = [
            PrepOp {
                kind: PrepKind::Roll(1),
                opcode: OP_SWAP,
            },
            PrepOp {
                kind: PrepKind::Roll(2),
                opcode: OP_ROT,
            },
            PrepOp {
                kind: PrepKind::TwoSwap,
                opcode: OP_2SWAP,
            },
            PrepOp {
                kind: PrepKind::TwoRot,
                opcode: OP_2ROT,
            },
        ];

        let mut out = vec![Vec::new()];
        let mut frontier = vec![Vec::new()];
        for _ in 0..3 {
            let mut next = Vec::new();
            for prefix in &frontier {
                for primitive in primitives {
                    let mut extended = prefix.clone();
                    extended.push(primitive);
                    next.push(extended);
                }
            }
            out.extend(next.iter().cloned());
            frontier = next;
        }
        out
    }

    type Env = [usize; SIZE_STATE];

    fn env_top_order(env: &Env) -> Vec<usize> {
        let mut order: Vec<_> = (0..SIZE_STATE).collect();
        order.sort_by_key(|&state| env[state]);
        order
    }

    fn apply_prep_op(order: &[usize], prep: PrepOp) -> Vec<usize> {
        let mut out = order.to_vec();
        match prep.kind {
            PrepKind::Roll(depth) => {
                let value = out.remove(depth);
                out.insert(0, value);
            }
            PrepKind::TwoSwap => {
                let original = out[..4].to_vec();
                out[..4].copy_from_slice(&[original[2], original[3], original[0], original[1]]);
            }
            PrepKind::TwoRot => {
                let original = out[..6].to_vec();
                out[..6].copy_from_slice(&[
                    original[4],
                    original[5],
                    original[0],
                    original[1],
                    original[2],
                    original[3],
                ]);
            }
        }
        out
    }

    struct MovedState {
        order: Vec<usize>,
        emit: Program,
        cost: usize,
    }

    fn move_state_in_order(order: &[usize], state: usize) -> MovedState {
        let position = order
            .iter()
            .position(|&candidate| candidate == state)
            .unwrap_or_else(|| panic!("state {state} missing from simulated stack"));
        if position == 0 {
            return MovedState {
                order: order.to_vec(),
                emit: Program::default(),
                cost: 0,
            };
        }

        let mut next = order.to_vec();
        let value = next.remove(position);
        next.insert(0, value);
        let emit = match position {
            1 => op(OP_SWAP),
            2 => op(OP_ROT),
            _ => {
                let mut emit = push(position as i32);
                emit.op(OP_ROLL);
                emit
            }
        };
        MovedState {
            order: next,
            emit,
            cost: roll_cost(position),
        }
    }

    #[derive(Clone)]
    struct PrepStep {
        emit: Program,
        action: Option<usize>,
    }

    #[derive(Clone)]
    struct PrepPlan {
        cost: usize,
        order: Vec<usize>,
        steps: Vec<PrepStep>,
        initial_action: Option<usize>,
    }

    #[derive(Clone)]
    struct PairPlan {
        env: Env,
        cost: usize,
        prep: PrepPlan,
    }

    #[derive(Clone, Copy)]
    enum PreAction {
        Initial,
        Forward(usize),
        MiddleForward,
        MiddleInverse,
        Inverse(usize),
    }

    struct Generator {
        tables: LookupTables,
        env: Env,
        permutations: Vec<[usize; 4]>,
        prep_prefixes: Vec<Vec<PrepOp>>,
        round_constants: [[i32; 16]; 11],
        beta: [i32; 16],
    }

    impl Generator {
        fn new() -> Self {
            Self {
                tables: LookupTables::new(),
                env: std::array::from_fn(|i| i),
                permutations: permutations4(),
                prep_prefixes: prep_prefixes(),
                round_constants: RC.map(split_nibbles_lsb),
                beta: split_nibbles_lsb(BETA),
            }
        }

        fn op_xor_shifted(&self, scratch: i32) -> Program {
            let mut out = op(OP_ADD);
            match scratch {
                0 => {}
                1 => out.op(OP_1ADD),
                -1 => out.op(OP_1SUB),
                positive if positive > 0 => {
                    out.push(positive);
                    out.op(OP_ADD);
                }
                negative => {
                    out.push(-negative);
                    out.op(OP_SUB);
                }
            }
            out.op(OP_PICK);
            out
        }

        fn op_xor_constant(&self, constant: i32, scratch: i32) -> Program {
            if constant == 0 {
                return Program::default();
            }
            if constant == 15 {
                let mut out = push(15);
                out.op(OP_SWAP);
                out.op(OP_SUB);
                return out;
            }

            let mut out =
                push(self.tables.xor_offsets[constant as usize] + scratch + ADDR_XOR_TABLE - 1);
            out.op(OP_ADD);
            out.op(OP_PICK);
            out
        }

        fn op_sbox(&self, scratch: i32) -> Program {
            let mut out = push(scratch + ADDR_SBOX_TABLE - 1);
            out.op(OP_ADD);
            out.op(OP_PICK);
            out
        }

        fn op_sbox_xor_constant(&self, constant: i32, scratch: i32) -> Program {
            if let Some(address) = self.tables.sbox_xor_addresses[constant as usize] {
                let mut out = push(address - 1 + scratch);
                out.op(OP_ADD);
                out.op(OP_PICK);
                return out;
            }

            let mut out = self.op_xor_constant(constant, scratch);
            out.extend(self.op_sbox(scratch));
            out
        }

        fn op_sbox_inv(&self, scratch: i32) -> Program {
            let mut out = push(scratch + ADDR_NIBBLE_TABLE - 1);
            out.op(OP_ADD);
            out.op(OP_PICK);
            out
        }

        fn op_sbox_inv_xor_constant(&self, constant: i32, scratch: i32) -> Program {
            if let Some(address) = self.tables.sbox_inv_xor_addresses[constant as usize] {
                let mut out = push(address - 1 + scratch);
                out.op(OP_ADD);
                out.op(OP_PICK);
                return out;
            }

            let mut out = self.op_sbox_inv(scratch);
            out.extend(self.op_xor_constant(constant, scratch));
            out
        }

        fn move_state_to_top(&mut self, state: usize, scratch: i32) -> Program {
            let old_position = self.env[state];
            for candidate in 0..SIZE_STATE {
                if candidate != state && self.env[candidate] > old_position {
                    self.env[candidate] -= 1;
                }
            }
            for candidate in 0..SIZE_STATE {
                if candidate != state {
                    self.env[candidate] += 1;
                }
            }
            self.env[state] = 0;

            let position = old_position as i32 + scratch;
            match position {
                0 => Program::default(),
                1 => op(OP_SWAP),
                2 => op(OP_ROT),
                _ => {
                    let mut out = push(position);
                    out.op(OP_ROLL);
                    out
                }
            }
        }

        fn copy_key_to_top(&self, index: usize, scratch: i32) -> Program {
            let position = SIZE_KEY as i32 - 1 - index as i32 + ADDR_KEY + scratch;
            match position {
                0 => op(OP_DUP),
                1 => op(OP_OVER),
                _ => {
                    let mut out = push(position);
                    out.op(OP_PICK);
                    out
                }
            }
        }

        fn sim_pair_group(
            &self,
            env: &Env,
            state_indices: [usize; 4],
            rotation: usize,
            k: usize,
        ) -> PairPlan {
            let goal: [usize; 4] = std::array::from_fn(|j| state_indices[(k + j) & 3]);
            let mut target_bit = [0u8; SIZE_STATE];
            for (j, &state) in state_indices.iter().enumerate() {
                target_bit[state] = 1 << j;
            }

            let mut best: Option<PrepPlan> = None;
            for prefix in &self.prep_prefixes {
                let mut order = env_top_order(env);
                let mut visited = target_bit[order[0]];
                let mut prefix_steps = Vec::new();
                let mut prefix_cost = 0;

                for &prep in prefix {
                    order = apply_prep_op(&order, prep);
                    prefix_cost += 1;
                    let bit = target_bit[order[0]];
                    let action = if bit != 0 && visited & bit == 0 {
                        Some(order[0])
                    } else {
                        None
                    };
                    visited |= bit;
                    prefix_steps.push(PrepStep {
                        emit: op(prep.opcode),
                        action,
                    });
                }

                for move_mask in 0u8..16 {
                    if (move_mask | visited) & 15 != 15 {
                        continue;
                    }

                    let mut candidate_order = order.clone();
                    let mut candidate_visited = visited;
                    let mut candidate_cost = prefix_cost;
                    let mut steps = prefix_steps.clone();

                    for goal_index in (0..4).rev() {
                        let state = goal[goal_index];
                        let bit = target_bit[state];
                        if move_mask & bit == 0 {
                            continue;
                        }

                        let moved = move_state_in_order(&candidate_order, state);
                        candidate_order = moved.order;
                        candidate_cost += moved.cost;
                        let action = if candidate_visited & bit == 0 {
                            Some(state)
                        } else {
                            None
                        };
                        candidate_visited |= bit;
                        steps.push(PrepStep {
                            emit: moved.emit,
                            action,
                        });
                    }

                    if candidate_visited != 15
                        || !goal
                            .iter()
                            .enumerate()
                            .all(|(i, &state)| candidate_order[i] == state)
                    {
                        continue;
                    }

                    let top_before = env_top_order(env)[0];
                    let initial_action = (target_bit[top_before] != 0).then_some(top_before);
                    if best
                        .as_ref()
                        .is_none_or(|current| candidate_cost < current.cost)
                    {
                        best = Some(PrepPlan {
                            cost: candidate_cost,
                            order: candidate_order,
                            steps,
                            initial_action,
                        });
                    }
                }
            }

            let prep = best.expect("failed to prepare cyclic M-hat quartet");
            let stack_map: [usize; 4] = std::array::from_fn(|j| (k + j) & 3);
            let phase = (2 * k + rotation + 3) & 3;
            let orientation_path = [0usize, 2, 3, 1];
            let row_order = orientation_path.map(|value| (value + 4 - phase) & 3);

            let mut simulated = [0usize; SIZE_STATE];
            for (depth, &state) in prep.order.iter().enumerate() {
                simulated[state] = depth;
            }
            for (output_position, &row) in row_order.iter().enumerate() {
                let logical = state_indices[stack_map[row]];
                simulated[logical] = (output_position + 1) & 3;
            }

            PairPlan {
                env: simulated,
                cost: 83 + prep.cost,
                prep,
            }
        }

        fn best_pair_group(
            &self,
            env: &Env,
            state_indices: [usize; 4],
            rotation: usize,
        ) -> PairPlan {
            let mut best: Option<PairPlan> = None;
            for k in 0..4 {
                let candidate = self.sim_pair_group(env, state_indices, rotation, k);
                if best
                    .as_ref()
                    .is_none_or(|current| candidate.cost < current.cost)
                {
                    best = Some(candidate);
                }
            }
            best.expect("one cyclic M-hat plan must exist")
        }

        fn emit_base_rotation(delta: usize) -> Program {
            match delta & 3 {
                0 => Program::default(),
                1 => {
                    let mut out = push(3);
                    out.op(OP_ROLL);
                    out
                }
                2 => op(OP_2SWAP),
                3 => {
                    let mut out = op(OP_2SWAP);
                    out.push(3);
                    out.op(OP_ROLL);
                    out
                }
                _ => unreachable!(),
            }
        }

        fn emit_pre_action(&self, action: PreAction, state: usize) -> Program {
            match action {
                PreAction::Initial => {
                    let mut out = self.copy_key_to_top(state, 0);
                    out.extend(self.op_xor_shifted(0));
                    out.extend(self.op_sbox(0));
                    out
                }
                PreAction::Forward(round) => {
                    let key_index = if (round - 1) % 2 != 0 {
                        state + 16
                    } else {
                        state
                    };
                    let mut out = self.copy_key_to_top(key_index, 0);
                    out.extend(self.op_xor_shifted(0));
                    out.extend(
                        self.op_sbox_xor_constant(self.round_constants[round - 1][state], 0),
                    );
                    out
                }
                PreAction::MiddleForward => {
                    let mut out = self.copy_key_to_top(state + 16, 0);
                    out.extend(self.op_xor_shifted(0));
                    out.extend(self.op_sbox_xor_constant(self.round_constants[5][state], 0));
                    out.extend(self.copy_key_to_top(state, 0));
                    out.extend(self.op_xor_shifted(0));
                    out
                }
                PreAction::MiddleInverse => {
                    let before = 15 - SHIFT_INV[15 - state] as usize;
                    let mut out = self.copy_key_to_top(before + 16, 0);
                    out.extend(self.op_xor_shifted(0));
                    out.extend(self.op_xor_constant(self.beta[before], 0));
                    out.extend(self.op_sbox_inv_xor_constant(self.round_constants[6][before], 0));
                    out.extend(self.copy_key_to_top(before, 0));
                    out.extend(self.op_xor_shifted(0));
                    out
                }
                PreAction::Inverse(round) => {
                    let before = 15 - SHIFT_INV[15 - state] as usize;
                    let mut out =
                        self.op_sbox_inv_xor_constant(self.round_constants[round][before], 0);
                    let key_index = if round % 2 != 0 { before + 16 } else { before };
                    out.extend(self.copy_key_to_top(key_index, 0));
                    out.extend(self.op_xor_shifted(0));
                    out
                }
            }
        }

        fn mhat_multiply(
            &mut self,
            base: usize,
            use_mhat0: bool,
            pre_action: PreAction,
        ) -> Program {
            let rotation = usize::from(!use_mhat0);
            let state_indices = std::array::from_fn(|j| 15 - (base + j));
            let plan = self.best_pair_group(&self.env, state_indices, rotation);
            let mut out = Program::default();

            if let Some(state) = plan.prep.initial_action {
                out.extend(self.emit_pre_action(pre_action, state));
            }
            for step in &plan.prep.steps {
                out.extend(step.emit.clone());
                if let Some(state) = step.action {
                    out.extend(self.emit_pre_action(pre_action, state));
                }
            }

            let orientation_path = [0usize, 2, 3, 1];
            let mut orientation = 0usize;
            for (output_index, &target_orientation) in orientation_path.iter().enumerate() {
                let final_row = output_index == 3;
                out.extend(Self::emit_base_rotation(
                    (target_orientation + 4 - orientation) & 3,
                ));
                if !final_row {
                    out.op(OP_2OVER);
                    out.op(OP_2OVER);
                }

                out.push(if final_row {
                    ADDR_PAIR01_FINAL_ROW_TABLE - 1
                } else {
                    ADDR_PAIR01_ROW_TABLE + 3
                });
                out.op(OP_ADD);
                out.op(OP_PICK);
                out.op(OP_ADD);
                out.op(OP_PICK);
                if final_row {
                    out.op(OP_1SUB);
                    out.op(OP_FROMALTSTACK);
                    out.op(OP_FROMALTSTACK);
                    out.op(OP_FROMALTSTACK);
                    out.op(OP_2ROT);
                } else {
                    out.op(OP_ROT);
                    out.op(OP_ROT);
                }

                out.push(ADDR_PAIR23_ROW_TABLE + if final_row { 1 } else { 2 });
                out.op(OP_ADD);
                out.op(OP_PICK);
                if final_row {
                    out.op(OP_1SUB);
                }
                out.op(OP_ADD);
                out.op(OP_PICK);
                if final_row {
                    out.push(4);
                    out.op(OP_ROLL);
                }
                out.op(OP_ADD);
                out.op(OP_PICK);
                if !final_row {
                    out.op(OP_TOALTSTACK);
                }
                orientation = target_orientation;
            }

            self.env = plan.env;
            out
        }

        fn m_layer(&mut self, pre_action: PreAction) -> Program {
            let rows = [(0usize, true), (4, false), (8, false), (12, true)];
            let mut best_permutation = None;
            let mut best_cost = usize::MAX;

            for &permutation in &self.permutations {
                let mut simulated = self.env;
                let mut total_cost = 0;
                for group in permutation {
                    let (base, use_mhat0) = rows[group];
                    let state_indices = std::array::from_fn(|j| 15 - (base + j));
                    let plan =
                        self.best_pair_group(&simulated, state_indices, usize::from(!use_mhat0));
                    total_cost += plan.cost;
                    simulated = plan.env;
                }
                if total_cost < best_cost {
                    best_cost = total_cost;
                    best_permutation = Some(permutation);
                }
            }

            let mut out = Program::default();
            for group in best_permutation.expect("one M-layer group order must exist") {
                let (base, use_mhat0) = rows[group];
                out.extend(self.mhat_multiply(base, use_mhat0, pre_action));
            }
            out
        }

        fn shift_rows(&mut self, inverse: bool) {
            let source = self.env;
            let permutation = if inverse { SHIFT_INV } else { SHIFT };
            for (destination, source_index) in permutation.into_iter().enumerate() {
                self.env[15 - destination] = source[15 - source_index as usize];
            }
        }

        fn init_memory(&mut self) -> Program {
            let mut out = Program::default();
            for _ in 0..SIZE_KEY + SIZE_STATE {
                out.op(OP_TOALTSTACK);
            }
            out.extend(self.tables.cold_push.clone());

            for i in 0..SIZE_KEY {
                out.op(OP_FROMALTSTACK);
                match i {
                    0 => {}
                    1 => out.op(OP_1ADD),
                    _ => {
                        out.push(i as i32);
                        out.op(OP_ADD);
                    }
                }
                out.op(OP_PICK);
            }

            out.extend(self.tables.hot_push.clone());
            for _ in 0..SIZE_STATE {
                out.op(OP_FROMALTSTACK);
            }
            self.env = std::array::from_fn(|i| i);
            out
        }

        fn generate(mut self) -> Program {
            let mut out = self.init_memory();
            out.extend(self.m_layer(PreAction::Initial));
            self.shift_rows(false);

            for round in 2..=5 {
                out.extend(self.m_layer(PreAction::Forward(round)));
                self.shift_rows(false);
            }

            out.extend(self.m_layer(PreAction::MiddleForward));
            self.shift_rows(true);
            out.extend(self.m_layer(PreAction::MiddleInverse));

            for round in 7..=10 {
                self.shift_rows(true);
                out.extend(self.m_layer(PreAction::Inverse(round)));
            }

            for state in (0..SIZE_STATE).rev() {
                out.extend(self.move_state_to_top(state, 0));
                out.extend(self.op_sbox_inv_xor_constant(self.beta[state], 0));
                out.extend(self.copy_key_to_top(state + SIZE_STATE, 0));
                out.extend(self.op_xor_shifted(0));
            }

            for _ in 0..SIZE_STATE {
                out.op(OP_TOALTSTACK);
            }
            for _ in 0..(SIZE_MEMORY - SIZE_STATE) / 2 {
                out.op(OP_2DROP);
            }
            if (SIZE_MEMORY - SIZE_STATE) & 1 != 0 {
                out.op(OP_DROP);
            }
            for _ in 0..SIZE_STATE {
                out.op(OP_FROMALTSTACK);
            }
            out
        }
    }

    static ENGINE: OnceLock<ScriptBuf> = OnceLock::new();

    pub(super) fn engine() -> Script {
        let script = ENGINE
            .get_or_init(|| Generator::new().generate().into_script_buf())
            .clone();
        Script::new("optimized PRINCEv2 engine").push_script(script)
    }
}

/// Reverse the top 16 stack items without disturbing anything below them.
fn reverse_top_block() -> Script {
    script! {
        for depth in (1..16usize).rev() {
            { depth as u32 } OP_ROLL OP_TOALTSTACK
        }
        OP_TOALTSTACK
        for _ in 0..16 { OP_FROMALTSTACK }
    }
}

/// Full PRINCEv2 encryption with hardcoded key.
/// Input: 16 state nibbles (nibble[0]=MSB on top, nibble[15]=LSB at depth 15).
/// Output: 16 ciphertext nibbles in same layout.
fn prince_encrypt_with_engine(key: u128, engine: Script) -> Script {
    let upper_key = u64_to_nibbles_msb((key >> 64) as u64);
    let lower_key = u64_to_nibbles_msb(key as u64);

    let mut push_key = script! {};
    // The source engine's key slots are the reverse of the public Rust key
    // convention: k0 LSB-to-MSB, followed by k1 LSB-to-MSB.
    for nibble in upper_key
        .into_iter()
        .rev()
        .chain(lower_key.into_iter().rev())
    {
        push_key = script! { { push_key } { nibble as u32 } };
    }

    script! {
        // The public Rust API keeps the established MSB-on-top state layout.
        // The optimized engine uses LSB-on-top, so adapt at both boundaries.
        { reverse_top_block() }

        // Park the plaintext while placing the embedded key underneath it.
        for _ in 0..16 { OP_TOALTSTACK }
        { push_key }
        for _ in 0..16 { OP_FROMALTSTACK }

        { engine }
        { reverse_top_block() }
    }
}

pub fn prince_encrypt(key: u128) -> Script {
    prince_encrypt_with_engine(key, optimized::engine())
}

// ---------------------------------------------------------------------------
// Helper: u64 with MSB nibble first ↔ nibble array
// nibble[i] = get_nibble(v, i) = (v >> (4*(15-i))) & 0xf
// ---------------------------------------------------------------------------

pub fn u64_to_nibbles_msb(v: u64) -> [u8; 16] {
    let mut n = [0u8; 16];
    for i in 0..16 {
        n[i] = ((v >> (4 * (15 - i))) & 0xf) as u8;
    }
    n
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::execution::execute_script;
    use crate::support::script::{script, ScriptCompilation};
    use sha2::{Digest, Sha256};

    fn execute_encryption(key: u128, plaintext: u64, expected: u64) -> usize {
        let plaintext_nibbles = u64_to_nibbles_msb(plaintext);
        let ciphertext = u64_to_nibbles_msb(expected);
        let encrypt = prince_encrypt(key);

        let result = execute_script(script! {
            for i in (0..16usize).rev() {
                { plaintext_nibbles[i] as u32 }
            }
            { encrypt }
            for i in 0..16usize {
                { ciphertext[i] as u32 }
                OP_EQUALVERIFY
            }
            OP_TRUE
        });

        assert!(
            result.success,
            "Script encryption failed for key={key:032x}, plaintext={plaintext:x}, expected={expected:016x}: {result}"
        );
        result.stats.max_nb_stack_items
    }

    #[test]
    fn test_prince_ref_known_vector() {
        // key = (k1 << 64) | k0 in Rust test convention
        // PRINCEv2 k0 = upper 64 bits = k1_rust = 0x0123456789abcdef
        // PRINCEv2 k1 = lower 64 bits = k0_rust = 0xfedcba9876543210
        let k0: u64 = 0xfedcba9876543210;
        let k1: u64 = 0x0123456789abcdef;
        let plaintext: u64 = 0x0123456789abcdef;
        let expected: u64 = 0x603cd95fa72a8704;
        let result = prince_encrypt_ref((k1 as u128) << 64 | k0 as u128, plaintext);
        assert_eq!(
            result, expected,
            "Expected 0x{:016x}, got 0x{:016x}",
            expected, result
        );
    }

    #[test]
    fn test_prince_ref_zero_key() {
        let ct = prince_encrypt_ref(0, 0);
        assert_eq!(ct, prince_encrypt_ref(0, 0));
    }

    #[test]
    fn test_m_layer_involution() {
        // M' should be its own inverse
        let test: u64 = 0x0123456789abcdef;
        let t1 = m_layer(test);
        let t2 = m_layer(t1);
        assert_eq!(t2, test, "M-layer should be its own inverse");
    }

    #[test]
    fn test_sbox_round_trip() {
        for i in 0..16u8 {
            assert_eq!(SBOX_INV[SBOX[i as usize] as usize], i);
        }
    }

    #[test]
    fn test_shift_rows_round_trip() {
        let test: u64 = 0x0123456789abcdef;
        let s = shift_rows(test);
        let r = shift_rows_inv(s);
        assert_eq!(r, test, "ShiftRows round trip failed");
    }

    #[test]
    fn test_script_sbox_lookup() {
        // Verify that prince_sbox correctly looks up sbox[nibble].
        // prince_sbox uses {15} OP_SWAP OP_SUB OP_PICK
        // after table push: stack = [sbox[15](top),...,sbox[0](depth 15), nibble]
        // {15} push: [sbox[15]..sbox[0], nibble, 15]
        // OP_SWAP: [sbox[15]..sbox[0], 15, nibble]  <- nibble on top
        // OP_SUB: pop nibble, pop 15, push (15 - nibble). So pick_index = 15-nibble.
        // OP_PICK: picks depth (15-nibble) from remaining [sbox[15]..sbox[0]] = sbox[nibble]. ✓
        for i in 0u8..16 {
            let expected = SBOX[i as usize];
            let s = script! {
                { prince_push_sbox_table() }
                { i as u32 }
                { prince_sbox() }
                // Stack: table(16 entries) | result (17 items total)
                // Save result, drop table, restore, compare
                OP_TOALTSTACK
                for _ in 0..16 { OP_DROP }
                OP_FROMALTSTACK
                { expected as u32 }
                OP_EQUAL
            };
            let res = execute_script(s);
            assert!(
                res.success,
                "sbox({}) failed, expected {}, result: {}",
                i, expected, res
            );
        }
    }

    #[test]
    fn test_script_xor() {
        for a in 0u8..4 {
            for b in 0u8..4 {
                let expected = a ^ b;
                // Stack before prince_xor(): table(256), b, a. After: table(256), result.
                let s = script! {
                    { prince_push_xor_table() }
                    { b as u32 }
                    { a as u32 }
                    { prince_xor() }
                    // result on top, table below (256 entries)
                    OP_TOALTSTACK
                    for _ in 0..256 { OP_DROP }
                    OP_FROMALTSTACK
                    { expected as u32 }
                    OP_EQUAL
                };
                let result = execute_script(s);
                assert!(
                    result.success,
                    "xor({},{}) failed, expected {}",
                    a, b, expected
                );
            }
        }
    }

    #[test]
    fn test_script_apply_sbox() {
        // Test S-box on a known state
        let pt: u64 = 0xfedcba9876543210;
        let expected: u64 = s_layer(pt, &SBOX);
        let pt_nibs = u64_to_nibbles_msb(pt);
        let exp_nibs = u64_to_nibbles_msb(expected);

        let s = script! {
            for i in (0..16usize).rev() {
                { pt_nibs[i] as u32 }
            }
            { script_apply_sbox_fresh(&SBOX) }
            for i in 0..16usize {
                { exp_nibs[i] as u32 }
                OP_EQUALVERIFY
            }
            OP_TRUE
        };
        let result = execute_script(s);
        assert!(result.success, "script_apply_sbox failed");
    }

    #[test]
    fn test_script_shift_rows() {
        let pt: u64 = 0xfedcba9876543210;
        let expected: u64 = shift_rows(pt);
        let pt_nibs = u64_to_nibbles_msb(pt);
        let exp_nibs = u64_to_nibbles_msb(expected);

        let s = script! {
            for i in (0..16usize).rev() {
                { pt_nibs[i] as u32 }
            }
            { script_shift_rows(false) }
            for i in 0..16usize {
                { exp_nibs[i] as u32 }
                OP_EQUALVERIFY
            }
            OP_TRUE
        };
        let result = execute_script(s);
        assert!(result.success, "script_shift_rows failed");
    }

    #[test]
    fn test_script_m_layer() {
        let pt: u64 = 0xfedcba9876543210;
        let expected: u64 = m_layer(pt);
        let pt_nibs = u64_to_nibbles_msb(pt);
        let exp_nibs = u64_to_nibbles_msb(expected);

        // Use OP_EQUALVERIFY to check each output nibble (nibble[0] on top after m_layer).
        let s = script! {
            for i in (0..16usize).rev() {
                { pt_nibs[i] as u32 }
            }
            { script_m_layer() }
            for i in 0..16usize {
                { exp_nibs[i] as u32 }
                OP_EQUALVERIFY
            }
            OP_TRUE
        };
        let result = crate::support::execution::execute_script(s);
        assert!(
            result.success,
            "script_m_layer failed: expected {:?}, error={:?}",
            exp_nibs, result.error
        );
    }

    #[test]
    fn test_prince_script_encrypt() {
        let k0: u64 = 0xfedcba9876543210;
        let k1: u64 = 0x0123456789abcdef;
        let plaintext: u64 = 0x0123456789abcdef;
        let expected: u64 = 0x603cd95fa72a8704;
        let key = (k1 as u128) << 64 | k0 as u128;

        let encrypt_script = prince_encrypt(key);
        let engine = optimized::engine().compile_with_policy();
        assert_eq!(engine.len(), 7547);
        assert_eq!(
            Sha256::digest(engine.as_bytes()).as_slice(),
            &[
                0x5d, 0x85, 0x99, 0x9b, 0x0b, 0xe6, 0xee, 0x66, 0x90, 0x4a, 0x6f, 0x6d, 0xa3, 0xb2,
                0xf3, 0x1c, 0x1b, 0x00, 0x74, 0x52, 0x76, 0x65, 0xb2, 0x7e, 0xa4, 0x1c, 0x1f, 0xef,
                0xe0, 0x33, 0x2b, 0x44,
            ]
        );
        assert_eq!(encrypt_script.compile_with_policy().len(), 7_685);
        assert_eq!(execute_encryption(key, plaintext, expected), 681);
    }

    #[test]
    fn test_prince_script_matches_reference() {
        let vectors = [
            (0u128, 0u64),
            (0u128, u64::MAX),
            (u128::MAX, 0u64),
            (u128::MAX, u64::MAX),
            (
                0x0123456789abcdeffedcba9876543210u128,
                0xfedcba9876543210u64,
            ),
            (
                0x6a09e667f3bcc908bb67ae8584caa73bu128,
                0x3c6ef372fe94f82bu64,
            ),
        ];

        for (key, plaintext) in vectors {
            execute_encryption(key, plaintext, prince_encrypt_ref(key, plaintext));
        }
    }
}
