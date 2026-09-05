//! All-branch combined-stack bounds for the hybrid Montgomery kernels.
//!
//! This analyzes the policy-produced bytecode, branching over both outcomes
//! of every conditional and both stack effects of IFDUP. Arithmetic values
//! are abstracted away, so impossible branches may only enlarge the bound.
//! Every profile has zero auxiliary witness hints; script-authored power
//! pools and actual G32 preserved prefixes are included in combined peaks.
//! Default mode checks the first callback. Pass `--all`, `--chained`,
//! `--persistent`, or `--terminal` for the additional bounded profiles.
//! No Script or scalar multiplication is executed by this static probe.

use std::collections::BTreeSet;

use bitcoin::script::Instruction;
use bitcoin_lab::{
    curves::ed25519::montgomery_slope::{
        verify_chained_transition_derived_hybrid_state_certified_u_next_u5_terminal_finalize_persistent_shared_power_pool,
        verify_chained_transition_derived_hybrid_state_initialize_persistent_shared_power_pool,
        verify_chained_transition_derived_hybrid_state_persistent_shared_power_pool,
        verify_first_transition_derived_hybrid_state_shared_power_pool,
        FIRST_DERIVED_COMPLETE_INPUT_ITEM_COUNT, HYBRID_CHAINED_DERIVED_COMPLETE_INPUT_ITEM_COUNT,
        HYBRID_CHAINED_U5_DERIVED_COMPLETE_INPUT_ITEM_COUNT, HYBRID_FIRST_SHARED_POWER_ITEM_COUNT,
        HYBRID_LATER_SHARED_POWER_ITEM_COUNT, HYBRID_STATE_ITEM_COUNT,
    },
    support::script::ScriptCompilation,
};

#[derive(Clone, Debug)]
enum Node {
    Basic { pc: usize, opcode: u8 },
    Conditional { yes: Vec<Node>, no: Vec<Node> },
}

fn parse(instructions: &[(usize, u8)], cursor: &mut usize) -> Vec<Node> {
    let mut result = Vec::new();
    while *cursor < instructions.len() {
        let (pc, opcode) = instructions[*cursor];
        if opcode == 0x67 || opcode == 0x68 {
            break;
        }
        *cursor += 1;
        if opcode == 0x63 || opcode == 0x64 {
            let yes = parse(instructions, cursor);
            let no = if instructions.get(*cursor).map(|(_, op)| *op) == Some(0x67) {
                *cursor += 1;
                parse(instructions, cursor)
            } else {
                Vec::new()
            };
            assert_eq!(instructions.get(*cursor).map(|(_, op)| *op), Some(0x68));
            *cursor += 1;
            result.push(Node::Conditional { yes, no });
        } else {
            result.push(Node::Basic { pc, opcode });
        }
    }
    result
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct State {
    main: usize,
    alt: usize,
}

#[derive(Default)]
struct Audit {
    peak: usize,
    peak_pc: usize,
    peak_opcode: u8,
    branches: usize,
    ifdup_count: usize,
    maximum_distinct_heights: usize,
}

fn step(state: State, opcode: u8) -> Vec<State> {
    let (required, removed, added) = match opcode {
        0x00 | 0x4f | 0x51..=0x60 => (0, 0, 1), // Parsed data pushes map to OP_0.
        0x61 | 0xab => (0, 0, 0),
        0x69 => (1, 1, 0),
        0x6a => return Vec::new(),
        0x6b if state.main != 0 => {
            return vec![State {
                main: state.main - 1,
                alt: state.alt + 1,
            }]
        }
        0x6c if state.alt != 0 => {
            return vec![State {
                main: state.main + 1,
                alt: state.alt - 1,
            }]
        }
        0x6b | 0x6c => return Vec::new(),
        0x6d => (2, 2, 0),
        0x6e => (2, 0, 2),
        0x6f => (3, 0, 3),
        0x70 => (4, 0, 2),
        0x71 => (6, 0, 0),
        0x72 => (4, 0, 0),
        0x73 if state.main != 0 => {
            return vec![
                state,
                State {
                    main: state.main + 1,
                    alt: state.alt,
                },
            ]
        }
        0x73 => return Vec::new(),
        0x74 => (0, 0, 1),
        0x75 => (1, 1, 0),
        0x76 => (1, 0, 1),
        0x77 => (2, 1, 0),
        0x78 => (2, 0, 1),
        0x79 => (2, 0, 0),
        0x7a => (2, 1, 0),
        0x7b => (3, 0, 0),
        0x7c => (2, 0, 0),
        0x7d => (2, 0, 1),
        0x82 => (1, 0, 1),
        0x87 | 0x93 | 0x94 | 0x9a | 0x9b | 0x9c | 0x9e..=0xa4 => (2, 1, 0),
        0x88 | 0x9d => (2, 2, 0),
        0x8b | 0x8c | 0x8f..=0x92 | 0xa6..=0xaa => (1, 0, 0),
        0xa5 => (3, 2, 0),
        _ => panic!("unhandled opcode {opcode:#x}; do not silently infer its stack effect"),
    };
    if state.main < required {
        return Vec::new();
    }
    vec![State {
        main: state.main - removed + added,
        alt: state.alt,
    }]
}

fn analyze(nodes: &[Node], mut states: BTreeSet<State>, audit: &mut Audit) -> BTreeSet<State> {
    for node in nodes {
        match node {
            Node::Basic { pc, opcode } => {
                if *opcode == 0x73 {
                    audit.ifdup_count += 1;
                }
                states = states
                    .into_iter()
                    .flat_map(|state| step(state, *opcode))
                    .collect();
                for state in &states {
                    if state.main + state.alt > audit.peak {
                        audit.peak = state.main + state.alt;
                        audit.peak_pc = *pc;
                        audit.peak_opcode = *opcode;
                    }
                }
            }
            Node::Conditional { yes, no } => {
                audit.branches += 1;
                let branch_states = states
                    .into_iter()
                    .filter_map(|state| {
                        (state.main > 0).then_some(State {
                            main: state.main.saturating_sub(1),
                            alt: state.alt,
                        })
                    })
                    .collect::<BTreeSet<_>>();
                states = analyze(yes, branch_states.clone(), audit);
                states.extend(analyze(no, branch_states, audit));
            }
        }
        audit.maximum_distinct_heights = audit.maximum_distinct_heights.max(states.len());
    }
    states
}

fn run_profile(profile: &str) -> usize {
    let (
        preserved,
        local_inputs,
        incoming_alt,
        outgoing_main,
        outgoing_alt,
        pool_items,
        expected_bytes,
        expected_peak,
    ) = match profile {
        "first" => (
            787,
            FIRST_DERIVED_COMPLETE_INPUT_ITEM_COUNT,
            0,
            HYBRID_STATE_ITEM_COUNT,
            0,
            HYBRID_FIRST_SHARED_POWER_ITEM_COUNT,
            33_409,
            991,
        ),
        "chained" => (
            771,
            HYBRID_CHAINED_DERIVED_COMPLETE_INPUT_ITEM_COUNT,
            0,
            HYBRID_STATE_ITEM_COUNT,
            HYBRID_LATER_SHARED_POWER_ITEM_COUNT,
            HYBRID_LATER_SHARED_POWER_ITEM_COUNT,
            46_401,
            995,
        ),
        "persistent" => (
            754,
            HYBRID_CHAINED_DERIVED_COMPLETE_INPUT_ITEM_COUNT,
            HYBRID_LATER_SHARED_POWER_ITEM_COUNT,
            HYBRID_STATE_ITEM_COUNT,
            HYBRID_LATER_SHARED_POWER_ITEM_COUNT,
            HYBRID_LATER_SHARED_POWER_ITEM_COUNT,
            46_368,
            994,
        ),
        "terminal" => (
            0,
            HYBRID_CHAINED_U5_DERIVED_COMPLETE_INPUT_ITEM_COUNT,
            HYBRID_LATER_SHARED_POWER_ITEM_COUNT,
            1,
            0,
            HYBRID_LATER_SHARED_POWER_ITEM_COUNT,
            43_236,
            283,
        ),
        _ => panic!("unknown profile {profile}"),
    };
    let fragment = match profile {
        "first" => verify_first_transition_derived_hybrid_state_shared_power_pool(preserved as u32),
        "chained" => verify_chained_transition_derived_hybrid_state_initialize_persistent_shared_power_pool(preserved as u32),
        "persistent" => verify_chained_transition_derived_hybrid_state_persistent_shared_power_pool(preserved as u32),
        "terminal" => verify_chained_transition_derived_hybrid_state_certified_u_next_u5_terminal_finalize_persistent_shared_power_pool(preserved as u32),
        _ => unreachable!(),
    }.compile_with_policy();
    assert_eq!(fragment.len(), expected_bytes);
    let instructions = fragment
        .instruction_indices()
        .map(|instruction| {
            let (pc, instruction) = instruction.expect("generated bytecode parses");
            (
                pc,
                match instruction {
                    Instruction::PushBytes(_) => 0,
                    Instruction::Op(opcode) => opcode.to_u8(),
                },
            )
        })
        .collect::<Vec<_>>();
    let mut cursor = 0;
    let nodes = parse(&instructions, &mut cursor);
    assert_eq!(cursor, instructions.len());
    let initial = State {
        main: preserved + local_inputs,
        alt: incoming_alt,
    };
    let mut audit = Audit {
        peak: initial.main + initial.alt,
        ..Audit::default()
    };
    let outputs = analyze(&nodes, BTreeSet::from([initial]), &mut audit);
    assert_eq!(
        outputs,
        BTreeSet::from([State {
            main: preserved + outgoing_main,
            alt: outgoing_alt,
        }])
    );
    println!("profile={profile} kernel_policy_bytes={} shared_power_items={pool_items} complete_local_data_items={local_inputs} incoming_main_items={} incoming_alt_items={incoming_alt} auxiliary_hint_items=0", fragment.len(), initial.main);
    println!(
        "all_branch_local_combined_stack_upper_bound={} peak_byte_offset={} peak_opcode={:#x}",
        audit.peak - preserved,
        audit.peak_pc,
        audit.peak_opcode
    );
    println!(
        "g32_preserved_items={preserved} all_branch_g32_combined_stack_upper_bound={}",
        audit.peak
    );
    println!("conditionals={} ifdup_instructions={} maximum_distinct_height_states={} exact_local_output_main_items={outgoing_main} exact_output_alt_items={outgoing_alt}", audit.branches, audit.ifdup_count, audit.maximum_distinct_heights);
    println!("evidence=locally-reproduced evidence_boundary=all-branch-static-stack-analysis execution_class=unclassified whole_leaf_generated=false whole_leaf_executed=false");
    assert_eq!(
        audit.peak, expected_peak,
        "all-branch {profile} analytical budget"
    );
    audit.peak
}

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("--all") => {
            let maximum = ["first", "chained", "persistent", "terminal"]
                .map(run_profile)
                .into_iter()
                .max()
                .unwrap();
            assert_eq!(maximum, 995);
            println!("maximum_all_branch_g32_kernel_frontier=995 auxiliary_hint_items_per_relation=0 auxiliary_hint_items_94_relations=0");
        }
        Some("--chained") => {
            run_profile("chained");
        }
        Some("--persistent") => {
            run_profile("persistent");
        }
        Some("--terminal") => {
            run_profile("terminal");
        }
        None | Some("--first") => {
            run_profile("first");
        }
        Some(other) => panic!("unknown mode {other}"),
    }
}
