pub fn pairs(count: usize) -> Vec<(i64, i64)> {
    let m = i64::from(i32::MAX);
    [(m, m), (-m, -m + 1), (-m, m), (0, -1)]
        .into_iter()
        .cycle()
        .take(count)
        .collect()
}

pub fn witness(pairs: &[(i64, i64)], explicit: bool) -> Vec<Vec<u8>> {
    pairs
        .iter()
        .flat_map(|&(a, b)| {
            let sum = a + b;
            [a, b, sum.div_euclid(2)]
                .into_iter()
                .chain(explicit.then_some(sum.rem_euclid(2)))
                .map(scriptnum)
        })
        .collect()
}

pub fn verify_batch(fragment: Script, pairs: &[(i64, i64)]) -> Script {
    script! {
        for (a, b) in pairs.iter().rev() {
            { fragment.clone() }
            { (a + b).div_euclid(2) } OP_EQUALVERIFY
        }
    }
}
