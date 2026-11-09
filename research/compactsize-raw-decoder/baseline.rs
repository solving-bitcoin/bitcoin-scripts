mod schedule {
    include!("../../src/support/compact_size/schedule.rs");
}

pub fn numeric() -> Script {
    schedule::decode_with(script! {253}, verify_canonical_byte())
}
