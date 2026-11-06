pub fn host_count(items: &[Vec<u8>], lag: u32) -> u32 {
    items
        .iter()
        .zip(items.iter().skip(lag as usize))
        .filter(|(left, right)| left == right)
        .count() as u32
}

pub fn periodic(width: u32) -> Vec<Vec<u8>> {
    (0..width)
        .map(|i| {
            let class = (i / 4 % 7) as u8;
            vec![class; (class % 3 + 1) as usize]
        })
        .collect()
}
