pub fn witness(reversed: &[bool]) -> Vec<Vec<u8>> {
    reversed
        .iter()
        .enumerate()
        .flat_map(|(index, &swapped)| {
            let [lo, hi] = (index as u16).to_le_bytes();
            let a = vec![0x81, lo, hi];
            let b = vec![0x01, lo, hi];
            let [c, d] = if swapped {
                [b.clone(), a.clone()]
            } else {
                [a.clone(), b.clone()]
            };
            [a, b, c, d]
        })
        .collect()
}
