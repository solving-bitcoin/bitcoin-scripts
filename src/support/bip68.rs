//! Host-side BIP68 sequence-lock preflight for confirmed transaction inputs.
//!
//! This mirrors Bitcoin Core v30.3 `CalculateSequenceLocks` and
//! `EvaluateSequenceLocks` with `LOCKTIME_VERIFY_SEQUENCE` enabled. It checks
//! relative maturity only. It does not establish UTXO existence, BIP113/
//! absolute locktime finality, script validity, coinbase maturity, or policy.
//! A caller must obtain the confirmation heights and median-time-past values
//! from the same candidate chain. An unsupported result is not a rejection.

use bitcoin::{OutPoint, Transaction};

const DISABLE_FLAG: u32 = 1 << 31;
const TYPE_FLAG: u32 = 1 << 22;
const LOCKTIME_MASK: u32 = 0x0000_ffff;
const TIME_GRANULARITY: u32 = 9;

/// Chain facts for one confirmed UTXO, in transaction input order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfirmedPrevoutContext {
    /// Must equal the transaction input's previous output.
    pub outpoint: OutPoint,
    /// Height of the block that confirmed this UTXO.
    pub confirmation_height: Option<u32>,
    /// MTP at `max(confirmation_height - 1, 0)`, needed for time locks.
    pub prior_block_mtp: Option<i64>,
}

/// The block in which the transaction is proposed for inclusion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CandidateBlockContext {
    pub height: Option<u32>,
    /// MTP of the candidate block's parent, as Core evaluates it.
    pub parent_mtp: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bip68UnsupportedReason {
    NoInputs,
    PrevoutCountMismatch,
    PrevoutMismatch { input_index: usize },
    MissingCandidateHeight,
    InvalidCandidateHeight,
    MissingCandidateParentMtp,
    InvalidCandidateParentMtp,
    MissingConfirmationHeight { input_index: usize },
    UnconfirmedPrevout { input_index: usize },
    MissingPriorBlockMtp { input_index: usize },
    InvalidPriorBlockMtp { input_index: usize },
    InconsistentMtp { input_index: usize },
}

/// Core's calculated lock pair uses the last invalid height and MTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bip68Verdict {
    Mature,
    Premature { min_height: i64, min_time: i64 },
    Unsupported(Bip68UnsupportedReason),
}

/// Evaluate BIP68 for a transaction with confirmed prevouts at a candidate block.
///
/// Inputs with the disable bit set do not contribute a sequence lock. Versions
/// below 2 also have no BIP68 lock. All prevout identities and confirmation
/// heights are still required, even when their sequences are disabled. Time
/// locks additionally require the MTP of the block before confirmation.
/// Missing or inconsistent facts yield `Unsupported`, never `Premature`.
pub fn evaluate_bip68_sequence_locks(
    tx: &Transaction,
    prevouts: &[ConfirmedPrevoutContext],
    candidate: &CandidateBlockContext,
) -> Bip68Verdict {
    use Bip68UnsupportedReason as Unsupported;

    if tx.input.is_empty() {
        return Bip68Verdict::Unsupported(Unsupported::NoInputs);
    }
    if prevouts.len() != tx.input.len() {
        return Bip68Verdict::Unsupported(Unsupported::PrevoutCountMismatch);
    }
    let Some(candidate_height) = candidate.height else {
        return Bip68Verdict::Unsupported(Unsupported::MissingCandidateHeight);
    };
    if candidate_height == 0 {
        return Bip68Verdict::Unsupported(Unsupported::InvalidCandidateHeight);
    }
    let Some(candidate_parent_mtp) = candidate.parent_mtp else {
        return Bip68Verdict::Unsupported(Unsupported::MissingCandidateParentMtp);
    };
    if !(0..=u32::MAX as i64).contains(&candidate_parent_mtp) {
        return Bip68Verdict::Unsupported(Unsupported::InvalidCandidateParentMtp);
    }

    let mut min_height = -1_i64;
    let mut min_time = -1_i64;
    for (index, (input, prevout)) in tx.input.iter().zip(prevouts).enumerate() {
        if input.previous_output != prevout.outpoint {
            return Bip68Verdict::Unsupported(Unsupported::PrevoutMismatch { input_index: index });
        }
        let Some(coin_height) = prevout.confirmation_height else {
            return Bip68Verdict::Unsupported(Unsupported::MissingConfirmationHeight {
                input_index: index,
            });
        };
        if coin_height >= candidate_height {
            return Bip68Verdict::Unsupported(Unsupported::UnconfirmedPrevout {
                input_index: index,
            });
        }
        if let Some(coin_mtp) = prevout.prior_block_mtp {
            if !(0..=u32::MAX as i64).contains(&coin_mtp) {
                return Bip68Verdict::Unsupported(Unsupported::InvalidPriorBlockMtp {
                    input_index: index,
                });
            }
            if coin_mtp > candidate_parent_mtp {
                return Bip68Verdict::Unsupported(Unsupported::InconsistentMtp {
                    input_index: index,
                });
            }
        }

        if tx.version.0 < 2 || input.sequence.0 & DISABLE_FLAG != 0 {
            continue;
        }
        let relative = (input.sequence.0 & LOCKTIME_MASK) as i64;
        if input.sequence.0 & TYPE_FLAG != 0 {
            let Some(coin_mtp) = prevout.prior_block_mtp else {
                return Bip68Verdict::Unsupported(Unsupported::MissingPriorBlockMtp {
                    input_index: index,
                });
            };
            min_time = min_time.max(coin_mtp + (relative << TIME_GRANULARITY) - 1);
        } else {
            min_height = min_height.max(coin_height as i64 + relative - 1);
        }
    }

    // Core requires the candidate height and its parent's MTP to be strictly
    // greater than the last-invalid values returned by CalculateSequenceLocks.
    if min_height >= candidate_height as i64 || min_time >= candidate_parent_mtp {
        Bip68Verdict::Premature {
            min_height,
            min_time,
        }
    } else {
        Bip68Verdict::Mature
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{absolute, transaction, ScriptBuf, Sequence, TxIn, Witness};

    fn input(vout: u32, sequence: u32) -> TxIn {
        TxIn {
            previous_output: OutPoint {
                txid: OutPoint::null().txid,
                vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::from_consensus(sequence),
            witness: Witness::new(),
        }
    }

    fn transaction_with(sequences: &[u32], version: i32) -> Transaction {
        Transaction {
            version: transaction::Version(version),
            lock_time: absolute::LockTime::ZERO,
            input: sequences
                .iter()
                .enumerate()
                .map(|(index, sequence)| input(index as u32, *sequence))
                .collect(),
            output: vec![],
        }
    }

    fn confirmed(
        tx: &Transaction,
        height: u32,
        prior_mtp: Option<i64>,
    ) -> Vec<ConfirmedPrevoutContext> {
        tx.input
            .iter()
            .map(|input| ConfirmedPrevoutContext {
                outpoint: input.previous_output,
                confirmation_height: Some(height),
                prior_block_mtp: prior_mtp,
            })
            .collect()
    }

    fn candidate(height: u32, parent_mtp: i64) -> CandidateBlockContext {
        CandidateBlockContext {
            height: Some(height),
            parent_mtp: Some(parent_mtp),
        }
    }

    #[test]
    fn height_locks_use_last_invalid_height_and_low_sixteen_bits() {
        let tx = transaction_with(&[5 | (1 << 20)], 2); // Reserved bits do not extend the lock.
        let prevouts = confirmed(&tx, 100, None);
        assert_eq!(
            evaluate_bip68_sequence_locks(&tx, &prevouts, &candidate(104, 1_000)),
            Bip68Verdict::Premature {
                min_height: 104,
                min_time: -1
            }
        );
        assert_eq!(
            evaluate_bip68_sequence_locks(&tx, &prevouts, &candidate(105, 1_000)),
            Bip68Verdict::Mature
        );
        let zero = transaction_with(&[0], 2);
        assert_eq!(
            evaluate_bip68_sequence_locks(
                &zero,
                &confirmed(&zero, 100, None),
                &candidate(101, 1_000)
            ),
            Bip68Verdict::Mature
        );
    }

    #[test]
    fn time_locks_use_prior_block_mtp_and_512_second_units() {
        let tx = transaction_with(&[TYPE_FLAG | 2 | (1 << 21)], 2);
        let prevouts = confirmed(&tx, 100, Some(10_000));
        assert_eq!(
            evaluate_bip68_sequence_locks(&tx, &prevouts, &candidate(110, 11_023)),
            Bip68Verdict::Premature {
                min_height: -1,
                min_time: 11_023
            }
        );
        assert_eq!(
            evaluate_bip68_sequence_locks(&tx, &prevouts, &candidate(110, 11_024)),
            Bip68Verdict::Mature
        );
        // An active zero time lock is mature when the parent MTP equals the
        // MTP before the funding block: 10_000 - 1 < 10_000.
        let zero = transaction_with(&[TYPE_FLAG], 2);
        assert_eq!(
            evaluate_bip68_sequence_locks(
                &zero,
                &confirmed(&zero, 100, Some(10_000)),
                &candidate(101, 10_000)
            ),
            Bip68Verdict::Mature
        );
    }

    #[test]
    fn every_input_contributes_and_disabled_or_old_version_inputs_do_not() {
        let tx = transaction_with(&[5, TYPE_FLAG | 2, DISABLE_FLAG | 65_535], 2);
        let mut prevouts = confirmed(&tx, 100, Some(10_000));
        prevouts[1].confirmation_height = Some(98);
        assert_eq!(
            evaluate_bip68_sequence_locks(&tx, &prevouts, &candidate(105, 11_023)),
            Bip68Verdict::Premature {
                min_height: 104,
                min_time: 11_023
            }
        );
        assert_eq!(
            evaluate_bip68_sequence_locks(&tx, &prevouts, &candidate(105, 11_024)),
            Bip68Verdict::Mature
        );
        let old = transaction_with(&[65_535, TYPE_FLAG | 65_535], 1);
        assert_eq!(
            evaluate_bip68_sequence_locks(
                &old,
                &confirmed(&old, 100, None),
                &candidate(101, 10_000)
            ),
            Bip68Verdict::Mature
        );
    }

    #[test]
    fn missing_or_inconsistent_chain_facts_never_become_premature_verdicts() {
        let tx = transaction_with(&[5, TYPE_FLAG | 2], 2);
        let mut prevouts = confirmed(&tx, 100, Some(10_000));
        let candidate = candidate(101, 10_000);
        assert_eq!(
            evaluate_bip68_sequence_locks(&tx, &prevouts[..1], &candidate),
            Bip68Verdict::Unsupported(Bip68UnsupportedReason::PrevoutCountMismatch)
        );
        prevouts[1].outpoint.vout = 7;
        assert_eq!(
            evaluate_bip68_sequence_locks(&tx, &prevouts, &candidate),
            Bip68Verdict::Unsupported(Bip68UnsupportedReason::PrevoutMismatch { input_index: 1 })
        );
        prevouts[1].outpoint = tx.input[1].previous_output;
        prevouts[1].confirmation_height = None;
        assert_eq!(
            evaluate_bip68_sequence_locks(&tx, &prevouts, &candidate),
            Bip68Verdict::Unsupported(Bip68UnsupportedReason::MissingConfirmationHeight {
                input_index: 1
            })
        );
        prevouts[1].confirmation_height = Some(101);
        assert_eq!(
            evaluate_bip68_sequence_locks(&tx, &prevouts, &candidate),
            Bip68Verdict::Unsupported(Bip68UnsupportedReason::UnconfirmedPrevout {
                input_index: 1
            })
        );
        prevouts[1].confirmation_height = Some(100);
        prevouts[1].prior_block_mtp = None;
        assert_eq!(
            evaluate_bip68_sequence_locks(&tx, &prevouts, &candidate),
            Bip68Verdict::Unsupported(Bip68UnsupportedReason::MissingPriorBlockMtp {
                input_index: 1
            })
        );
        prevouts[1].prior_block_mtp = Some(10_001);
        assert_eq!(
            evaluate_bip68_sequence_locks(&tx, &prevouts, &candidate),
            Bip68Verdict::Unsupported(Bip68UnsupportedReason::InconsistentMtp { input_index: 1 })
        );
        assert_eq!(
            evaluate_bip68_sequence_locks(
                &tx,
                &confirmed(&tx, 100, Some(10_000)),
                &CandidateBlockContext {
                    height: None,
                    parent_mtp: Some(10_000)
                }
            ),
            Bip68Verdict::Unsupported(Bip68UnsupportedReason::MissingCandidateHeight)
        );
        assert_eq!(
            evaluate_bip68_sequence_locks(
                &tx,
                &confirmed(&tx, 100, Some(10_000)),
                &CandidateBlockContext {
                    height: Some(101),
                    parent_mtp: None
                }
            ),
            Bip68Verdict::Unsupported(Bip68UnsupportedReason::MissingCandidateParentMtp)
        );
    }
}
