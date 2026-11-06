pub fn values(width: u32) -> Vec<i64> {
    let m = i64::from(i32::MAX);
    (0..width)
        .map(|index| {
            let i = i64::from(index);
            if i % 2 == 0 {
                m - i
            } else {
                -m + i - 1
            }
        })
        .collect()
}
