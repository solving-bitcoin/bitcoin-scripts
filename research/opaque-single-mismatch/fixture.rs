pub fn single_difference(width: u32, mismatch: u32) -> Vec<Vec<u8>> {
    (0..width)
        .flat_map(|index| {
            let left = (index as u16).to_le_bytes().to_vec();
            let right = if index == mismatch { vec![0xff] } else { left.clone() };
            [left, right]
        })
        .collect()
}
