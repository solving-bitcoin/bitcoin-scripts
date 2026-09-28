//! JSON-stdin adapter for the confirmed-prevout BIP68 preflight.
//!
//! Accepts one transaction input. It reports `unsupported` when the request
//! omits chain facts; that is a no-verdict outcome, not a consensus rejection.

use bitcoin::{consensus::encode::deserialize_hex, Transaction};
use bitcoin_lab::support::bip68::{
    evaluate_bip68_sequence_locks, Bip68Verdict, CandidateBlockContext, ConfirmedPrevoutContext,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::io::{self, Read};

#[derive(Deserialize)]
struct Request {
    tx_hex: Option<String>,
    funding_height: Option<u32>,
    funding_parent_mtp: Option<i64>,
    candidate_height: Option<u32>,
    candidate_parent_mtp: Option<i64>,
}

fn unsupported(reason: &str) -> Value {
    json!({"verdict": "unsupported", "reason": reason})
}

fn evaluate(request: Request) -> Value {
    let Some(hex) = request.tx_hex else {
        return unsupported("missing_tx_hex");
    };
    let tx: Transaction = match deserialize_hex(&hex) {
        Ok(tx) => tx,
        Err(_) => return unsupported("invalid_tx_hex"),
    };
    let txid = tx.compute_txid().to_string();
    if tx.input.len() != 1 {
        return json!({
            "verdict": "unsupported",
            "reason": "requires_one_input",
            "txid": txid,
        });
    }
    let outpoint = tx.input[0].previous_output;
    let prevout = ConfirmedPrevoutContext {
        outpoint,
        confirmation_height: request.funding_height,
        prior_block_mtp: request.funding_parent_mtp,
    };
    let candidate = CandidateBlockContext {
        height: request.candidate_height,
        parent_mtp: request.candidate_parent_mtp,
    };
    let mut output = json!({
        "txid": txid,
        "input_outpoint": outpoint.to_string(),
    });
    match evaluate_bip68_sequence_locks(&tx, &[prevout], &candidate) {
        Bip68Verdict::Mature => output["verdict"] = json!("mature"),
        Bip68Verdict::Premature {
            min_height,
            min_time,
        } => {
            output["verdict"] = json!("premature");
            output["min_height"] = json!(min_height);
            output["min_time"] = json!(min_time);
        }
        Bip68Verdict::Unsupported(reason) => {
            output["verdict"] = json!("unsupported");
            output["reason"] = json!(format!("{reason:?}"));
        }
    }
    output
}

fn main() {
    let mut input = String::new();
    let result = match io::stdin().read_to_string(&mut input) {
        Ok(_) => match serde_json::from_str::<Request>(&input) {
            Ok(request) => evaluate(request),
            Err(_) => unsupported("invalid_request_json"),
        },
        Err(_) => unsupported("stdin_read_failed"),
    };
    println!("{result}");
}
