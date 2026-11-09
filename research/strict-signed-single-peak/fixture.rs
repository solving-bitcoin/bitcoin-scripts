pub fn values(width: usize, peak: usize) -> Vec<i64> {
    (0..width)
        .map(|i| if i <= peak {
            50 * i as i64
        } else {
            50 * peak as i64 - 37 * (i - peak) as i64
        })
        .collect()
}
