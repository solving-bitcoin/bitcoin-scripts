pub fn payloads(n: u32) -> Vec<Vec<u8>> {
    (0..n).map(|i| (i as u16).to_le_bytes().to_vec()).collect()
}

pub fn scriptnum(n: u32) -> Vec<u8> {
    let mut bytes = [0; 8];
    let len = bitcoin::script::write_scriptint(&mut bytes, i64::from(n));
    bytes[..len].to_vec()
}
