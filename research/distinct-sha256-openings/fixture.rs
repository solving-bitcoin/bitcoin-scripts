pub fn pool(n: usize) -> (Vec<Vec<u8>>, Vec<[u8; 32]>) {
    let preimages: Vec<_> = (0..n)
        .map(|index| {
            let mut value = vec![0x42; 32];
            value[..4].copy_from_slice(&(index as u32).to_le_bytes());
            value
        })
        .collect();
    let digests = preimages
        .iter()
        .map(|preimage| sha256::Hash::hash(preimage).to_byte_array())
        .collect();
    (preimages, digests)
}

pub fn scriptnum(n: usize) -> Vec<u8> {
    let mut bytes = [0; 8];
    let len = bitcoin::script::write_scriptint(&mut bytes, n as i64);
    bytes[..len].to_vec()
}
