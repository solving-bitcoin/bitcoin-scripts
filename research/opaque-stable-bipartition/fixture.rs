pub fn alternating(pair_count: u32) -> Vec<(Vec<u8>, bool)> {
    (0..pair_count)
        .map(|i| ((i as u16).to_le_bytes().to_vec(), i % 2 == 0))
        .collect()
}

pub fn witness(records: &[(Vec<u8>, bool)]) -> Vec<Vec<u8>> {
    records
        .iter()
        .flat_map(|(payload, flag)| [payload.clone(), if *flag { vec![1] } else { vec![] }])
        .collect()
}

pub fn verify_outputs(records: &[(Vec<u8>, bool)]) -> Script {
    let (true_items, false_items): (Vec<_>, Vec<_>) =
        records.iter().partition(|(_, flag)| *flag);
    script! {
        { false_items.len() } OP_EQUALVERIFY
        for (payload, _) in false_items.into_iter().rev() {
            { payload.clone() } OP_EQUALVERIFY
        }
        for (payload, _) in true_items.into_iter().rev() {
            OP_FROMALTSTACK { payload.clone() } OP_EQUALVERIFY
        }
    }
}
