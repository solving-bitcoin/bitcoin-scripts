//! Optional, bounded experiments in PRINCEv2 stack scheduling.
//!
//! `cargo test --locked --release --lib compare_stack_schedule_candidates -- --ignored --nocapture`
//! runs the short search. Set `PRINCE_SCHEDULE_EXTENDED=1` to include wider beams
//! and longer preparation prefixes. Candidate schedules are experimental and
//! do not change the production generator.

use super::*;

#[test]
#[ignore = "focused stack-schedule search"]
fn compare_stack_schedule_candidates() {
    use crate::support::script::ScriptCompilation;

    #[derive(Clone)]
    struct Beam {
        env: Env,
        cost: usize,
        path: Vec<[usize; 4]>,
    }
    fn terminal_cost(env: &Env) -> usize {
        let mut remaining = env_top_order(env);
        let mut cost = 0;
        for state in (0..SIZE_STATE).rev() {
            let depth = remaining.iter().position(|&value| value == state).unwrap();
            cost += roll_cost(depth);
            remaining.remove(depth);
        }
        cost
    }
    fn shift(env: Env, inverse: bool) -> Env {
        let mut next = env;
        for (destination, source) in if inverse { SHIFT_INV } else { SHIFT }
            .into_iter()
            .enumerate()
        {
            next[15 - destination] = env[15 - source as usize];
        }
        next
    }
    fn compile_schedule(mut generator: Generator, path: &[[usize; 4]]) -> ScriptBuf {
        let mut out = generator.init_memory();
        let actions = [
            PreAction::Initial,
            PreAction::Forward(2),
            PreAction::Forward(3),
            PreAction::Forward(4),
            PreAction::Forward(5),
            PreAction::MiddleForward,
            PreAction::MiddleInverse,
            PreAction::Inverse(7),
            PreAction::Inverse(8),
            PreAction::Inverse(9),
            PreAction::Inverse(10),
        ];
        for (layer, (&action, order)) in actions.iter().zip(path).enumerate() {
            for &group in order {
                out.extend(generator.mhat_multiply(group * 4, group == 0 || group == 3, action));
            }
            if layer < 10 {
                generator.shift_rows(layer >= 5);
            }
        }
        let mut remaining = env_top_order(&generator.env);
        for state in (0..SIZE_STATE).rev() {
            let scratch = remaining.len() as i32 - SIZE_STATE as i32;
            let moved = move_state_in_order(&remaining, state);
            out.extend(moved.emit);
            out.extend(generator.op_sbox_inv_xor_constant(
                generator.beta[state] ^ generator.key[state + SIZE_STATE],
                scratch,
            ));
            out.op(OP_TOALTSTACK);
            remaining = moved.order;
            remaining.remove(0);
        }
        for _ in 0..(generator.tables.memory_size - SIZE_STATE) / 2 {
            out.op(OP_2DROP);
        }
        if (generator.tables.memory_size - SIZE_STATE) & 1 != 0 {
            out.op(OP_DROP);
        }
        for _ in 0..SIZE_STATE {
            out.op(OP_FROMALTSTACK);
        }
        Script::new("schedule candidate")
            .push_script(out.into_script_buf())
            .compile_with_policy()
    }

    let generator = Generator::new(0);
    let baseline = Script::new("baseline")
        .push_script(Generator::new(0).generate().into_script_buf())
        .compile_with_policy();
    eprintln!("schedule baseline bytes={}", baseline.len());
    let extended = std::env::var_os("PRINCE_SCHEDULE_EXTENDED").is_some();
    let widths: &[usize] = if extended { &[1, 4, 8, 32] } else { &[1, 8] };
    for &width in widths {
        let started = std::time::Instant::now();
        let mut beam = vec![Beam {
            env: generator.env,
            cost: 0,
            path: Vec::new(),
        }];
        for layer in 0..11 {
            let mut distinct = HashMap::<Env, Beam>::new();
            for node in &beam {
                for &permutation in &generator.permutations {
                    let mut candidate = node.clone();
                    for group in permutation {
                        let indices = std::array::from_fn(|j| 15 - (group * 4 + j));
                        let plan = generator.best_pair_group(
                            &candidate.env,
                            indices,
                            usize::from(group == 1 || group == 2),
                        );
                        candidate.cost += plan.cost;
                        candidate.env = plan.env;
                    }
                    if layer < 10 {
                        candidate.env = shift(candidate.env, layer >= 5);
                    } else {
                        candidate.cost += terminal_cost(&candidate.env);
                    }
                    candidate.path.push(permutation);
                    let entry = distinct
                        .entry(candidate.env)
                        .or_insert_with(|| candidate.clone());
                    if candidate.cost < entry.cost {
                        *entry = candidate;
                    }
                }
            }
            beam = distinct.into_values().collect();
            beam.sort_by(|left, right| (&left.cost, &left.path).cmp(&(&right.cost, &right.path)));
            beam.truncate(width);
        }
        let best = &beam[0];
        let compiled = compile_schedule(Generator::new(0), &best.path);
        eprintln!(
            "schedule width={width} modeled_cost={} bytes={} millis={} path={:?}",
            best.cost,
            compiled.len(),
            started.elapsed().as_millis(),
            best.path
        );
    }

    #[derive(Clone)]
    struct QuartetBeam {
        env: Env,
        cost: usize,
        used: u8,
        path: Vec<(usize, usize)>,
    }
    let configurations: &[(usize, usize)] = if extended {
        &[(3, 128), (4, 128), (5, 32)]
    } else {
        &[(3, 8)]
    };
    for &(maximum_prefix, width) in configurations {
        let mut plans = HashMap::new();
        let mut generator = Generator::new(0);
        let primitives: Vec<_> = generator
            .prep_prefixes
            .iter()
            .filter(|prefix| prefix.len() == 1)
            .map(|prefix| prefix[0])
            .collect();
        for length in 4..=maximum_prefix {
            let mut extended = Vec::new();
            for prefix in generator
                .prep_prefixes
                .iter()
                .filter(|prefix| prefix.len() == length - 1)
            {
                for &primitive in &primitives {
                    let mut next = prefix.clone();
                    next.push(primitive);
                    extended.push(next);
                }
            }
            generator.prep_prefixes.extend(extended);
        }
        let started = std::time::Instant::now();
        let mut beam = vec![QuartetBeam {
            env: generator.env,
            cost: 0,
            used: 0,
            path: Vec::new(),
        }];
        for layer in 0..11 {
            for depth in 0..4 {
                let mut distinct = HashMap::<(Env, u8), QuartetBeam>::new();
                for node in &beam {
                    for group in 0..4 {
                        if node.used & (1 << group) != 0 {
                            continue;
                        }
                        let indices = std::array::from_fn(|j| 15 - (group * 4 + j));
                        let rotation = usize::from(group == 1 || group == 2);
                        for k in 0..4 {
                            let plan = plans
                                .entry((node.env, indices, rotation, k))
                                .or_insert_with(|| {
                                    generator.sim_pair_group(&node.env, indices, rotation, k)
                                });
                            let mut candidate = node.clone();
                            candidate.cost += plan.cost;
                            candidate.env = plan.env;
                            candidate.used |= 1 << group;
                            candidate.path.push((group, k));
                            if depth == 3 {
                                if layer < 10 {
                                    candidate.env = shift(candidate.env, layer >= 5);
                                } else {
                                    candidate.cost += terminal_cost(&candidate.env);
                                }
                                candidate.used = 0;
                            }
                            let entry = distinct
                                .entry((candidate.env, candidate.used))
                                .or_insert_with(|| candidate.clone());
                            if candidate.cost < entry.cost {
                                *entry = candidate;
                            }
                        }
                    }
                }
                beam = distinct.into_values().collect();
                beam.sort_by(|left, right| {
                    (&left.cost, &left.path).cmp(&(&right.cost, &right.path))
                });
                beam.truncate(width);
            }
        }
        let best = &beam[0];
        eprintln!("quartet schedule maximum_prefix={maximum_prefix} width={width} modeled_cost={} millis={} path={:?}", best.cost, started.elapsed().as_millis(), best.path);
    }
}
