use super::*;

/// Leave the common modulo-three table below ordered canonical residues.
pub(super) fn project_for_windows(n: u32) -> Script {
    script! {
        {push_mod3_table()}
        {mod3_to_altstack(n, verify_canonical_nibble())}
        for _ in 0..n {OP_FROMALTSTACK}
    }
}

/// Copy and sum the top window without consuming it.
pub(super) fn sum_top_window(window: u32) -> Script {
    script! {
        0
        for depth in 1..=window {{depth} OP_PICK OP_ADD}
    }
}
