/// Greedily match each right item and remove its first equal left item.
pub fn verify_greedy(n: u32) -> Script {
    script! {
        for remaining in (2..=n).rev() {
            for depth in 0..remaining - 1 {
                {remaining + depth} OP_PICK OP_OVER OP_EQUAL
                OP_IF
                    OP_DROP
                    {remaining - 1 + depth} OP_ROLL OP_DROP
                OP_ELSE
            }
            {2 * remaining - 1} OP_ROLL OP_EQUALVERIFY
            for _ in 0..remaining - 1 {
                OP_ENDIF
            }
        }
        OP_EQUALVERIFY
    }
}

pub fn hint_depths(left: &[Vec<u8>], right: &[Vec<u8>]) -> Option<Vec<usize>> {
    if left.len() != right.len() || left.is_empty() {
        return None;
    }
    let mut pool = left.to_vec();
    let mut hints = vec![0; right.len() - 1];
    for (index, item) in right.iter().enumerate().skip(1).rev() {
        let position = pool.iter().rposition(|candidate| candidate == item)?;
        hints[index - 1] = pool.len() - 1 - position;
        pool.remove(position);
    }
    (pool[0] == right[0]).then_some(hints)
}

pub fn num(value: i64) -> Vec<u8> {
    let mut bytes = [0; 8];
    let len = bitcoin::script::write_scriptint(&mut bytes, value);
    bytes[..len].to_vec()
}

pub fn witness(left: &[Vec<u8>], right: &[Vec<u8>], hints: Option<&[usize]>) -> Vec<Vec<u8>> {
    let mut items = left.to_vec();
    for (index, payload) in right.iter().enumerate() {
        items.push(payload.clone());
        if let Some(hints) = hints.filter(|_| index > 0) {
            items.push(num(hints[index - 1] as i64));
        }
    }
    items
}
