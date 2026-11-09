pub fn values(width: usize) -> Vec<u8> {
    (0..width).map(|i| ((7*i+i/3+5)%16) as u8).collect()
}

pub fn checks(values: &[u8]) -> (u8, u8) {
    let sum: usize = values.iter().map(|&digit| digit as usize).sum();
    let weighted: usize = values.iter().enumerate().map(|(i,&digit)| i * digit as usize).sum();
    ((sum%17) as u8, (weighted%17) as u8)
}

pub fn item(value: u8) -> Vec<u8> {
    if value == 0 { vec![] } else { vec![value] }
}

pub fn witness(values: &[u8], erased: usize) -> Vec<Vec<u8>> {
    values.iter().enumerate().filter_map(|(i,&digit)| (i!=erased).then(|| item(digit))).collect()
}
