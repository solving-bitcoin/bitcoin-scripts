pub fn preimage(length: usize) -> Vec<u8> {
    (0..length)
        .map(|i| (i as u8).wrapping_mul(17).wrapping_add(length as u8))
        .collect()
}

pub fn commitments(first: usize, count: usize) -> Vec<[u8; 32]> {
    (first..first + count)
        .map(|length| preimage_length_commitment(&preimage(length)))
        .collect()
}
