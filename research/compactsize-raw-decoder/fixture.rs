pub fn scriptnum(value: i64) -> Vec<u8> {
    let mut bytes = [0; 8];
    let len = bitcoin::script::write_scriptint(&mut bytes, value);
    bytes[..len].to_vec()
}

pub fn items(wire: &[u8], raw: bool) -> Vec<Vec<u8>> {
    wire.iter()
        .rev()
        .map(|&byte| {
            if raw {
                vec![byte]
            } else {
                scriptnum(i64::from(byte))
            }
        })
        .collect()
}
