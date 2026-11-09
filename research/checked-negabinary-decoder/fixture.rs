pub fn bits(mut value: i64, width: u32) -> Vec<Vec<u8>> {
    let mut result = Vec::new();
    for _ in 0..width {
        let bit = value.rem_euclid(2);
        result.push(scriptnum(bit));
        value = (bit - value) / 2;
    }
    assert_eq!(value, 0, "value does not fit in the chosen negative-base width");
    result
}

pub fn values(count: usize) -> Vec<i64> {
    [-2_147_483_647, 1_431_655_765, -1, 0]
        .into_iter().cycle().take(count).collect()
}

pub fn witness(values: &[i64], width: u32) -> Vec<Vec<u8>> {
    values.iter().flat_map(|&value| bits(value, width)).collect()
}

pub fn verify_batch(fragment: Script, values: &[i64]) -> Script {
    script! {
        for &value in values.iter().rev() {
            { fragment.clone() } { value } OP_EQUALVERIFY
        }
    }
}
