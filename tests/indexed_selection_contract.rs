//! Witness and composition contracts for fixed-count sparse selection.
use bitcoin::ScriptBuf;
use bitcoin_lab::support::{
    execution::ExecuteInfo,
    indexed_selection::compact_indexed_items,
    script::*,
    tapscript::{execute_tapscript, TapscriptOutcome, TapscriptProfile},
};
use bitcoin_scriptexec::ExecError;

fn num(value: i64) -> Vec<u8> {
    let mut bytes = [0; 8];
    let len = bitcoin::script::write_scriptint(&mut bytes, value);
    bytes[..len].to_vec()
}

fn expected(payloads: &[Vec<u8>], flags: &[bool]) -> Vec<Vec<u8>> {
    let mut output: Vec<_> = payloads
        .iter()
        .zip(flags)
        .filter(|(_, keep)| **keep)
        .map(|(payload, _)| payload.clone())
        .collect();
    output.push(num(output.len() as i64));
    output
}

fn leaf(fragment: Script, output: &[Vec<u8>]) -> Script {
    script! {
        {fragment}
        for item in output.iter().rev() {{item.clone()} OP_EQUALVERIFY}
        OP_TRUE
    }
}

fn run(script: ScriptBuf, witness: Vec<Vec<u8>>) -> ExecuteInfo {
    match execute_tapscript(script, witness, TapscriptProfile::Consensus).outcome {
        TapscriptOutcome::Executed(result) => result,
        outcome => panic!("expected execution, got {outcome:?}"),
    }
}

fn clean(result: &ExecuteInfo) {
    assert!(result.stack_limit_enforced);
    assert_eq!(result.error, None, "{result}");
    assert!(result.success, "{result}");
    assert_eq!(result.final_stack.len(), 1);
    assert_eq!(result.final_stack.get(0), vec![1]);
}

fn rejects(result: &ExecuteInfo, expected: ExecError) {
    assert!(result.stack_limit_enforced);
    assert_eq!(result.error, Some(expected), "{result}");
    assert!(!result.success);
}

fn indexed_input(payloads: &[Vec<u8>], depths: &[i64]) -> Vec<Vec<u8>> {
    payloads
        .iter()
        .cloned()
        .chain(depths.iter().rev().map(|&depth| num(depth)))
        .collect()
}

#[test]
fn indexed_selection_matches_every_nonempty_small_subset() {
    let payloads = [
        vec![],
        vec![0x80],
        vec![0xf0; 520],
        vec![0xaa; 5],
        vec![0xff, 0x01],
        vec![1],
        vec![0],
        vec![0x81],
    ];
    for n in 1..=payloads.len() {
        let payloads = &payloads[..n];
        for mask in 1..1usize << n {
            let flags: Vec<_> = (0..n).map(|i| mask >> i & 1 == 1).collect();
            let depths: Vec<_> = (0..n)
                .filter(|&depth| flags[n - 1 - depth])
                .map(|depth| depth as i64)
                .collect();
            let fragment = compact_indexed_items(n as u32, depths.len() as u32);
            clean(&run(
                leaf(fragment, &expected(payloads, &flags)).compile_with_policy(),
                indexed_input(payloads, &depths),
            ));
        }
    }
}

#[test]
fn indexed_selection_rejects_hostile_controls_and_wrong_leaf_bindings() {
    let payloads: Vec<_> = (0..5).map(|i| vec![0x20 + i]).collect();
    let fragment = compact_indexed_items(5, 3);
    // Accept every payload selection on the fragment alone. A malformed
    // selector therefore has to fail before a terminal predicate can mask it.
    let cleanup = script! {{fragment.clone()} OP_2DROP OP_2DROP OP_TRUE}.compile_with_policy();
    let valid = indexed_input(&payloads, &[0, 2, 4]);
    clean(&run(cleanup.clone(), valid.clone()));
    for depths in [
        [0, 0, 4],
        [0, 4, 2],
        [-1, 2, 4],
        [0, 2, 5],
        [0, 2, 2147483647],
    ] {
        rejects(
            &run(cleanup.clone(), indexed_input(&payloads, &depths)),
            ExecError::Verify,
        );
    }
    for position in payloads.len()..valid.len() {
        let mut padded = valid.clone();
        padded[position].push(0);
        rejects(&run(cleanup.clone(), padded), ExecError::EqualVerify);
        for (bad, error) in [
            (vec![0x80], ExecError::EqualVerify),
            (vec![0; 5], ExecError::ScriptIntNumericOverflow),
            (vec![0; 521], ExecError::PushSize),
        ] {
            let mut witness = valid.clone();
            witness[position] = bad;
            rejects(&run(cleanup.clone(), witness), error);
        }
    }
    let mut oversized_discard = valid.clone();
    oversized_discard[1] = vec![0; 521];
    rejects(&run(cleanup, oversized_discard), ExecError::PushSize);

    let leaf = leaf(
        fragment,
        &expected(&payloads, &[true, false, true, false, true]),
    )
    .compile_with_policy();
    clean(&run(leaf.clone(), valid.clone()));
    assert!(!run(leaf.clone(), indexed_input(&payloads, &[0, 1, 4])).success);
    for position in 0..valid.len() {
        let mut short = valid.clone();
        short.remove(position);
        assert!(!run(leaf.clone(), short).success);
    }
    let mut extra = valid;
    extra.insert(0, vec![0x7f]);
    assert!(!run(leaf, extra).success);
}

#[test]
fn indexed_selection_output_alone_cannot_bind_equal_payload_positions() {
    let payloads = [vec![0x36], vec![0x36]];
    let expected = expected(&payloads, &[true, false]);
    let compiled = leaf(compact_indexed_items(2, 1), &expected).compile_with_policy();
    clean(&run(compiled.clone(), indexed_input(&payloads, &[0])));
    clean(&run(compiled, indexed_input(&payloads, &[1])));
}

#[test]
fn indexed_selection_preserves_caller_stacks_and_meets_its_exact_peak_bound() {
    for (n, k) in [(1, 1), (5, 3), (993, 1), (994, 1), (992, 4), (995, 1)] {
        let payloads: Vec<_> = (0..n).map(|i: u32| i.to_le_bytes().to_vec()).collect();
        let mut flags = vec![false; n as usize];
        let depths: Vec<_> = (0..k)
            .map(|j| {
                let depth = if k == 1 { n - 1 } else { j * (n - 1) / (k - 1) };
                flags[(n - 1 - depth) as usize] = true;
                i64::from(depth)
            })
            .collect();
        let fragment = compact_indexed_items(n, k);
        let suffix = indexed_input(&payloads, &depths);
        let output = expected(&payloads, &flags);
        let compiled = leaf(fragment.clone(), &output).compile_with_policy();
        let result = run(compiled, suffix.clone());
        clean(&result);
        assert_eq!(result.stats.max_nb_stack_items, (n + k + 4) as usize);

        let caller = script! {OP_TOALTSTACK {fragment} OP_FROMALTSTACK}.compile_with_policy();
        let mut witness = vec![vec![0x36, 0x51]];
        witness.extend(suffix);
        witness.push(vec![0x91, 0x22]);
        let result = run(caller, witness);
        if n + k + 6 <= 1000 {
            assert_eq!(result.error, None);
            let expected: Vec<_> = [vec![0x36, 0x51]]
                .into_iter()
                .chain(output)
                .chain([vec![0x91, 0x22]])
                .collect();
            let actual: Vec<_> = (0..result.final_stack.len())
                .map(|i| result.final_stack.get(i))
                .collect();
            assert_eq!(actual, expected);
            assert_eq!(result.stats.max_nb_stack_items, (n + k + 6) as usize);
        } else {
            rejects(&result, ExecError::StackSize);
        }
    }
    for (n, k) in [(0, 0), (1, 0), (1, 2), (993, 4), (u32::MAX, 1)] {
        assert!(std::panic::catch_unwind(|| compact_indexed_items(n, k)).is_err());
    }
}
