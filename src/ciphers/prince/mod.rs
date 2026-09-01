// PRINCEv2 block cipher implementation
// Reference: "PRINCEv2 – More Security for (Almost) No Overhead"
// rub-hgi/princev2 reference implementation
//
// 64-bit block, 128-bit key (k0 || k1, each 64 bits, big-endian nibble order)
// Nibble 0 = MSB nibble (bits 63:60), nibble 15 = LSB nibble (bits 3:0)

use bitcoin::ScriptBuf;

use crate::treepp::{script, Script};

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

// Generated by the optimized PRINCEv2 generator pinned below. The engine takes
// 32 key nibbles followed by 16 plaintext nibbles, with each half/block pushed
// most-significant nibble first (and therefore least-significant nibble on top).
//
// Source:
// https://github.com/BitVM/bitvm-js/blob/b931a6711ab332fd5923e708c869bed02e39984e/scripts/opcodes/PRINCEv2/prince_v2_optimized10.js
// SHA-256: 5d85999b0be6ee66904a6f6da3b2f31c1b0074527665b27ea41c1fefe0332b44
const OPTIMIZED_ENGINE_BYTES: &[u8; 7547] = include_bytes!("prince_v2_optimized10.bin");

fn optimized_engine() -> Script {
    Script::new("optimized PRINCEv2 engine")
        .push_script(ScriptBuf::from_bytes(OPTIMIZED_ENGINE_BYTES.to_vec()))
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
    prince_encrypt_with_engine(key, optimized_engine())
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
    use crate::execute_script;
    use crate::treepp::script;

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
        let result = crate::execute_script(s);
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
        assert_eq!(OPTIMIZED_ENGINE_BYTES.len(), 7547);
        assert_eq!(encrypt_script.compile().len(), 7735);
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
