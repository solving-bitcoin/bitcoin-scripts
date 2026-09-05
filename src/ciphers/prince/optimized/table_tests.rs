//! Optional, bounded table-layout experiments; final sizes use the compilation policy.
use super::*;

#[test]
fn mhat_core_cost_matches_planner() {
    let mut generator = Generator::new(0);
    assert_eq!(generator.tables.memory_size, 626);
    for (base, use_mhat0) in [(0, true), (4, false), (8, false), (12, true)] {
        let indices = std::array::from_fn(|j| 15 - (base + j));
        let plan = generator.best_pair_group(&generator.env, indices, usize::from(!use_mhat0));
        let pre_action_bytes: usize = indices
            .into_iter()
            .map(|state| {
                generator
                    .emit_pre_action(PreAction::Initial, state)
                    .byte_len()
            })
            .sum();
        assert_eq!(
            generator
                .mhat_multiply(base, use_mhat0, PreAction::Initial)
                .byte_len(),
            plan.cost + pre_action_bytes
        );
    }
}

#[test]
#[ignore = "focused table-selection experiment"]
fn compare_fused_row_candidates() {
    use crate::support::script::ScriptCompilation;
    let generator = Generator::new(0);
    let order = generator.tables.order.clone();
    eprintln!(
        "selected raw cost {} memory {} order {:?}",
        generator.table_cost(),
        generator.tables.memory_size,
        order
    );
    for index in 0..order.len() {
        if !order[index].starts_with('F') && !order[index].starts_with('I') {
            continue;
        }
        let mut candidate = order.clone();
        candidate.remove(index);
        let mut generator = Generator::new(0);
        generator.tables = LookupTables::from_order(&candidate);
        let cost = generator.table_cost();
        let memory = generator.tables.memory_size;
        let raw = generator.generate().into_script_buf();
        let compiled = Script::new("row candidate")
            .push_script(raw)
            .compile_with_policy();
        eprintln!(
            "remove {}: score={cost} memory={memory} bytes={}",
            order[index],
            compiled.len()
        );
    }
}

#[test]
#[ignore = "bounded table-layout synthesis"]
fn search_fused_row_layout() {
    use crate::support::script::ScriptCompilation;
    let mut generator = Generator::new(0);
    for pass in 0..16 {
        let order = generator.tables.order.clone();
        let mut best_order = order.clone();
        let mut best_cost = (generator.table_cost(), generator.tables.memory_size);
        for from in 1..order.len() {
            for to in 1..order.len() {
                let mut candidate = order.clone();
                let row = candidate.remove(from);
                candidate.insert(to, row);
                generator.tables = LookupTables::from_order(&candidate);
                let cost = (generator.table_cost(), generator.tables.memory_size);
                if cost < best_cost {
                    best_cost = cost;
                    best_order = candidate;
                }
            }
        }
        generator.tables = LookupTables::from_order(&best_order);
        eprintln!("pass={pass} cost={best_cost:?} order={best_order:?}");
        if best_order == order {
            break;
        }
    }
    let compiled = Script::new("layout candidate")
        .push_script(generator.generate().into_script_buf())
        .compile_with_policy();
    eprintln!("FINAL bytes={}", compiled.len());
}
