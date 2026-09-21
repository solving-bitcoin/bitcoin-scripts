//! Offchain subset-to-binary-label tables. This is NOT public setup verification
//! and does not repair the anchored point lock's unresolved extraction argument.
//! All keys, including candidate scalars, are deterministic PUBLIC test fixtures.
use bitcoin::{
    hashes::{sha256, Hash},
    secp256k1::{PublicKey, Secp256k1, SecretKey},
};
use num_bigint::BigUint;
use serde_json::json;
use std::time::Instant;

const N: usize = 50;
const POOLS: usize = 115;
const BITS: usize = 18;
const LABEL: usize = 16;
const BODY: usize = BITS * LABEL;
const MAX_ROW: usize = BODY + 16;
const DOMAIN: &str = "bitcoin-lab/subset-translation/v1/public-test-fixture";
type Selection = [usize; 4];
type Labels = [[[u8; LABEL]; 2]; BITS];

fn fixture(domain: &[u8], index: usize) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key(DOMAIN);
    h.update(domain);
    h.update(&(index as u64).to_le_bytes());
    *h.finalize().as_bytes()
}

struct Pool {
    secrets: Vec<[u8; 32]>,
    points: Vec<[u8; 33]>,
    labels: Labels,
    commitments: [[[u8; 32]; 2]; BITS],
    row_prefix: blake3::Hasher,
    row_mac: bool,
}
impl Pool {
    fn new(id: usize) -> Self {
        // Match the point scalars of the actual anchored publication fixture.
        let secp = Secp256k1::new();
        let mut secrets = vec![];
        let mut points = vec![];
        for i in 0..N {
            for attempt in 0.. {
                let secret = sha256::Hash::hash(
                    format!("anchored-publication-v1-{id}-{i}-{attempt}").as_bytes(),
                )
                .to_byte_array();
                let key = SecretKey::from_slice(&secret).unwrap();
                let point = PublicKey::from_secret_key(&secp, &key).serialize();
                if point[1] == 0 || point[1] >= 128 {
                    continue;
                }
                secrets.push(secret);
                points.push(point);
                break;
            }
        }
        // One common free-XOR delta, kept secret. No zero labels are public.
        let mut delta = fixture(b"global-delta", 0);
        delta[0] |= 1;
        let mut labels = [[[0; LABEL]; 2]; BITS];
        for (bit, pair) in labels.iter_mut().enumerate() {
            pair[0].copy_from_slice(&fixture(b"wire-zero", id * BITS + bit)[..LABEL]);
            for i in 0..LABEL {
                pair[1][i] = pair[0][i] ^ delta[i];
            }
        }
        let commitments = labels.map(|pair| pair.map(|label| *blake3::hash(&label).as_bytes()));
        let mut row_prefix = blake3::Hasher::new_derive_key(DOMAIN);
        row_prefix.update(b"row-key");
        row_prefix.update(&(id as u64).to_le_bytes());
        Self {
            secrets,
            points,
            labels,
            commitments,
            row_prefix,
            row_mac: true,
        }
    }
    fn row_bytes(&self) -> usize {
        BODY + if self.row_mac { 16 } else { 0 }
    }
    fn row_key(&self, selected: Selection, supplied: &[[u8; 32]; 4]) -> [u8; 32] {
        let mut h = self.row_prefix.clone();
        for (index, secret) in selected.iter().zip(supplied) {
            h.update(&(*index as u64).to_le_bytes());
            h.update(secret);
        }
        *h.finalize().as_bytes()
    }
    fn secret_tuple(&self, selected: Selection) -> [[u8; 32]; 4] {
        selected.map(|i| self.secrets[i])
    }
    fn plaintext(&self, rank: usize) -> [u8; BODY] {
        let mut out = [0; BODY];
        for bit in 0..BITS {
            out[bit * LABEL..(bit + 1) * LABEL]
                .copy_from_slice(&self.labels[bit][(rank >> bit) & 1]);
        }
        out
    }
    #[cfg(test)]
    fn encrypt(&self, selected: Selection, rank: usize, out: &mut [u8]) {
        let key = self.row_key(selected, &self.secret_tuple(selected));
        self.encrypt_key(&key, rank, out);
    }
    fn encrypt_key(&self, key: &[u8; 32], rank: usize, out: &mut [u8]) {
        pad(key, &mut out[..BODY]);
        for bit in 0..BITS {
            for j in 0..LABEL {
                out[bit * LABEL + j] ^= self.labels[bit][(rank >> bit) & 1][j];
            }
        }
        if self.row_mac {
            let tag = mac(key, &out[..BODY]);
            out[BODY..].copy_from_slice(&tag);
        }
    }
    fn open(
        &self,
        selected: Selection,
        supplied: &[[u8; 32]; 4],
        row: &[u8],
    ) -> Option<[u8; BODY]> {
        if row.len() != self.row_bytes()
            || selected[3] >= N
            || !selected.windows(2).all(|w| w[0] < w[1])
        {
            return None;
        }
        let secp = Secp256k1::new();
        for (i, bytes) in selected.iter().zip(supplied) {
            let key = SecretKey::from_slice(bytes).ok()?;
            if PublicKey::from_secret_key(&secp, &key).serialize() != self.points[*i] {
                return None;
            }
        }
        let key = self.row_key(selected, supplied);
        if self.row_mac && mac(&key, &row[..BODY]) != row[BODY..] {
            return None;
        }
        let mut out = [0; BODY];
        pad(&key, &mut out);
        for i in 0..BODY {
            out[i] ^= row[i];
        }
        if !self.row_mac {
            let rank = rank_subset(selected);
            for bit in 0..BITS {
                if blake3::hash(&out[bit * LABEL..(bit + 1) * LABEL]).as_bytes()
                    != &self.commitments[bit][(rank >> bit) & 1]
                {
                    return None;
                }
            }
        }
        Some(out)
    }
    fn generate(&self) -> Vec<u8> {
        let width = self.row_bytes();
        let mut table = vec![0; choose(N, 4) * width];
        self.row_keys(|key, rank| {
            self.encrypt_key(&key, rank, &mut table[rank * width..(rank + 1) * width])
        });
        table
    }
    fn check_opened_table(&self, table: &[u8]) -> bool {
        // Requires EVERY candidate scalar and BOTH wire labels. This is a full
        // opened-table audit for cut-and-choose, NOT public verification.
        let width = self.row_bytes();
        if table.len() != choose(N, 4) * width {
            return false;
        }
        let mut ok = true;
        self.row_keys(|key, rank| {
            let mut expected = [0; MAX_ROW];
            self.encrypt_key(&key, rank, &mut expected[..width]);
            ok &= expected[..width] == table[rank * width..(rank + 1) * width];
        });
        ok
    }
    fn row_keys(&self, mut f: impl FnMut([u8; 32], usize)) {
        // Cache real shared hash prefixes. Generated keys remain byte-identical
        // to hashing each full ordered scalar tuple independently.
        let extend = |prefix: &blake3::Hasher, index: usize| {
            let mut h = prefix.clone();
            h.update(&(index as u64).to_le_bytes());
            h.update(&self.secrets[index]);
            h
        };
        let mut rank = 0;
        for a in 0..N - 3 {
            let ha = extend(&self.row_prefix, a);
            for b in a + 1..N - 2 {
                let hb = extend(&ha, b);
                for c in b + 1..N - 1 {
                    let hc = extend(&hb, c);
                    for d in c + 1..N {
                        f(*extend(&hc, d).finalize().as_bytes(), rank);
                        rank += 1;
                    }
                }
            }
        }
        assert_eq!(rank, choose(N, 4));
    }
}
fn pad(key: &[u8; 32], out: &mut [u8]) {
    let mut h = blake3::Hasher::new_keyed(key);
    h.update(b"subset-row-pad-v1");
    h.finalize_xof().fill(out);
}
fn mac(key: &[u8; 32], body: &[u8]) -> [u8; 16] {
    let mut h = blake3::Hasher::new_keyed(key);
    h.update(b"subset-row-mac-v1");
    h.update(body);
    h.finalize().as_bytes()[..16].try_into().unwrap()
}
fn choose(n: usize, k: usize) -> usize {
    if k > n {
        return 0;
    }
    (0..k.min(n - k)).fold(1, |v, j| v * (n - j) / (j + 1))
}
#[cfg(test)]
fn subsets(n: usize, mut f: impl FnMut(Selection, usize)) {
    let mut rank = 0;
    for a in 0..n - 3 {
        for b in a + 1..n - 2 {
            for c in b + 1..n - 1 {
                for d in c + 1..n {
                    f([a, b, c, d], rank);
                    rank += 1;
                }
            }
        }
    }
    assert_eq!(rank, choose(n, 4));
}
fn rank_subset(selected: Selection) -> usize {
    let mut rank = 0;
    let mut start = 0;
    for (j, &index) in selected.iter().enumerate() {
        for skipped in start..index {
            rank += choose(N - skipped - 1, 3 - j);
        }
        start = index + 1;
    }
    rank
}
fn parallel<T: Send>(n: usize, workers: usize, job: impl Fn(usize) -> T + Sync) -> Vec<T> {
    std::thread::scope(|scope| {
        let job = &job;
        let handles: Vec<_> = (0..workers)
            .map(|worker| {
                scope.spawn(move || {
                    (worker..n)
                        .step_by(workers)
                        .map(|id| (id, job(id)))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        let mut indexed: Vec<_> = handles
            .into_iter()
            .flat_map(|h| h.join().unwrap())
            .collect();
        indexed.sort_by_key(|(id, _)| *id);
        indexed.into_iter().map(|(_, v)| v).collect()
    })
}
fn unhex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn check_native_recovery(
    pools: &[Pool],
    tables: &[Vec<u8>],
    report: &serde_json::Value,
) -> serde_json::Value {
    assert_eq!(pools.len(), POOLS);
    let records = report["recovery"]["extractions"].as_array().unwrap();
    assert_eq!(records.len(), POOLS * 4);
    let mut value = BigUint::from(0u8);
    let mut factor = BigUint::from(1u8);
    for i in 0..POOLS {
        let mut selected: Vec<_> = records
            .iter()
            .filter(|r| r["pool"].as_u64().unwrap() == i as u64)
            .collect();
        selected.sort_by_key(|r| r["label"].as_u64().unwrap());
        assert_eq!(selected.len(), 4);
        let indices: Selection =
            std::array::from_fn(|j| selected[j]["label"].as_u64().unwrap() as usize);
        let secrets: [[u8; 32]; 4] = std::array::from_fn(|j| {
            unhex(selected[j]["scalar"].as_str().unwrap())
                .try_into()
                .unwrap()
        });
        for j in 0..4 {
            assert_eq!(
                pools[i].points[indices[j]].as_slice(),
                unhex(selected[j]["target"].as_str().unwrap())
            );
        }
        let rank = rank_subset(indices);
        let width = pools[i].row_bytes();
        let decoded = pools[i]
            .open(
                indices,
                &secrets,
                &tables[i][rank * width..(rank + 1) * width],
            )
            .unwrap();
        assert_eq!(decoded, pools[i].plaintext(rank));
        value += &factor * rank;
        factor *= choose(N, 4);
    }
    let payload = unhex(report["recovery"]["payload_hex"].as_str().unwrap());
    assert_eq!(payload.len(), 256);
    assert_eq!(value, BigUint::from_bytes_be(&payload));
    json!({"scope":"Uses scalar extraction records from the existing Core report; no new Core run and no full garbled verifier evaluation.",
        "pools":POOLS,"scalars_from_core_report":POOLS*4,"binary_input_labels_recovered":POOLS*BITS,
        "payload_matches_core_report":true,"publication_vbytes":report["combined_vbytes"]})
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    let arg = |name: &str, default| {
        args.iter()
            .position(|v| v == name)
            .map_or(default, |i| args[i + 1].parse::<usize>().unwrap())
    };
    // Full table generation is intentionally opt-in: ~8.05 GB per sample.
    let count = arg("--pools", 1).clamp(1, POOLS);
    let workers = arg("--workers", 1).clamp(1, count);
    let samples = arg("--samples", 1).max(1);
    let row_mac = !args.iter().any(|v| v == "--label-hash-auth");
    let width = BODY + if row_mac { 16 } else { 0 };
    let native_report = args.iter().position(|v| v == "--native-recovery").map(|i| {
        let bytes = std::fs::read(&args[i + 1]).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        (parsed, sha256::Hash::hash(&bytes).to_string())
    });
    let mut native_check = serde_json::Value::Null;
    let mut rows = vec![];
    for _ in 0..samples {
        let start = Instant::now();
        let pools = parallel(count, workers, |id| {
            let mut p = Pool::new(id);
            p.row_mac = row_mac;
            p
        });
        let preparation_ms = start.elapsed().as_secs_f64() * 1000.;
        let start = Instant::now();
        let tables = parallel(count, workers, |i| pools[i].generate());
        let generation_ms = start.elapsed().as_secs_f64() * 1000.;
        let start = Instant::now();
        let checks = parallel(count, workers, |i| pools[i].check_opened_table(&tables[i]));
        let opened_audit_ms = start.elapsed().as_secs_f64() * 1000.;
        assert!(checks.into_iter().all(|v| v));
        // Selected real scalar openings of first/last rows, each pool. All
        // source scalars are the same public fixtures as the native prototype.
        let start = Instant::now();
        for i in 0..count {
            for (selected, rank) in [([0, 1, 2, 3], 0), ([46, 47, 48, 49], choose(N, 4) - 1)] {
                let decoded = pools[i]
                    .open(
                        selected,
                        &pools[i].secret_tuple(selected),
                        &tables[i][rank * width..(rank + 1) * width],
                    )
                    .unwrap();
                assert_eq!(decoded, pools[i].plaintext(rank));
            }
        }
        let selected_opening_check_ms = start.elapsed().as_secs_f64() * 1000.;
        if let Some((report, _)) = &native_report {
            native_check = check_native_recovery(&pools, &tables, report);
        }
        // Digest the actual retained bytes, outside setup timers. Detects
        // accidental skipped writes; this is not a public correctness proof.
        let mut digest = blake3::Hasher::new();
        for table in &tables {
            digest.update(table);
        }
        rows.push(json!({"preparation_ms":preparation_ms,"table_generation_ms":generation_ms,
            "opened_table_audit_ms":opened_audit_ms,"generation_plus_opened_audit_ms":preparation_ms+generation_ms+opened_audit_ms,
            "selected_opening_check_ms":selected_opening_check_ms,
            "table_digest_blake3":digest.finalize().to_hex().to_string()}));
    }
    println!("{}",serde_json::to_string_pretty(&json!({
        "evidence":"locally-reproduced","deployment":"unclassified",
        "scope":"All selected pool tables retained in RAM. Includes allocation, writes and worker startup. Opened audit requires every scalar and both labels; no public setup verification, VSS, garbled verifier, message-decoder circuit, point-lock scripts/transactions, process startup or compilation.",
        "security_status":"Conditional translation only; not a solution to point-lock extraction or malicious setup. Deterministic public secrets are fixtures.",
        "build_profile":if cfg!(debug_assertions){"debug"}else{"release"},
        "pools":count,"n":N,"t":4,"bits_per_pool":BITS,"workers":workers,
        "rows_per_pool":choose(N,4),"rows_total":count*choose(N,4),
        "authentication":if row_mac {"row-mac-128"}else{"public-label-hash-256"},
        "label_commitment_bytes":if row_mac {0}else{count*BITS*2*32},
        "row_bytes":width,"table_bytes":count*choose(N,4)*width,
        "native_recovery_report_sha256":native_report.as_ref().map(|(_,digest)|digest),
        "native_recovery_check":native_check,
        "samples":rows,
    })).unwrap());
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_subset_ranks_once_and_translation_opens() {
        let pool = Pool::new(0);
        // Exhaustive reduced domain, full-size scalar/label cryptography.
        subsets(8, |selection, rank| {
            let mut row = [0; MAX_ROW];
            pool.encrypt(selection, rank, &mut row);
            assert_eq!(
                pool.open(selection, &pool.secret_tuple(selection), &row),
                Some(pool.plaintext(rank))
            );
        });
    }
    #[test]
    fn wrong_scalar_order_index_row_and_modified_ciphertext_reject() {
        let pool = Pool::new(0);
        let selected = [0, 1, 2, 3];
        let secrets = pool.secret_tuple(selected);
        let mut row = [0; MAX_ROW];
        pool.encrypt(selected, 0, &mut row);
        assert!(pool.open([0, 1, 2, 4], &secrets, &row).is_none());
        assert!(pool.open([1, 0, 2, 3], &secrets, &row).is_none());
        assert!(pool.open([0, 1, 2, 50], &secrets, &row).is_none());
        assert!(pool.open([0, 1, 2, 2], &secrets, &row).is_none());
        assert!(pool.open(selected, &secrets, &row[..MAX_ROW - 1]).is_none());
        let mut wrong = secrets;
        wrong[3] = pool.secrets[4];
        assert!(pool.open(selected, &wrong, &row).is_none());
        let mut changed = row;
        changed[1] ^= 1;
        assert!(pool.open(selected, &secrets, &changed).is_none());
        let mut changed = row;
        changed[MAX_ROW - 1] ^= 1;
        assert!(pool.open(selected, &secrets, &changed).is_none());
        let other = Pool::new(1);
        assert!(other.open(selected, &secrets, &row).is_none());
    }
    #[test]
    fn public_points_cannot_certify_row_plaintext() {
        let good = Pool::new(0);
        let mut bad = Pool::new(0);
        bad.labels[0][0][0] ^= 1;
        assert_eq!(good.points, bad.points);
        let selected = [0, 1, 2, 3];
        let mut wrong_table_row = [0; MAX_ROW];
        bad.encrypt(selected, 0, &mut wrong_table_row);
        // Point checks and MAC both pass, but the prebound output label is wrong.
        let opened = good
            .open(selected, &good.secret_tuple(selected), &wrong_table_row)
            .unwrap();
        assert_ne!(opened, good.plaintext(0));
    }
    #[test]
    fn label_hash_auth_checks_all_bits_and_rejects_wrong_rank_or_labels() {
        let mut pool = Pool::new(0);
        pool.row_mac = false;
        subsets(8, |selection, _| {
            let rank = rank_subset(selection);
            let mut row = [0; BODY];
            pool.encrypt(selection, rank, &mut row);
            let secrets = pool.secret_tuple(selection);
            assert_eq!(
                pool.open(selection, &secrets, &row),
                Some(pool.plaintext(rank))
            );
            for bit in 0..BITS {
                let mut bad = row;
                bad[bit * LABEL] ^= 1;
                assert!(pool.open(selection, &secrets, &bad).is_none());
            }
            pool.encrypt(selection, rank ^ 1, &mut row);
            assert!(pool.open(selection, &secrets, &row).is_none());
        });
        // The MAC-free variation detects the malicious row only AFTER opening.
        // Existing public points/label commitments do not certify its contents.
        let mut bad = Pool::new(0);
        bad.row_mac = false;
        bad.labels[0][0][0] ^= 1;
        assert_eq!(pool.points, bad.points);
        assert_eq!(pool.commitments, bad.commitments);
        let mut row = [0; BODY];
        bad.encrypt([0, 1, 2, 3], 0, &mut row);
        assert!(pool
            .open([0, 1, 2, 3], &pool.secret_tuple([0, 1, 2, 3]), &row)
            .is_none());
    }
    #[test]
    fn full_pool_rank_matches_table_order() {
        subsets(N, |selection, rank| {
            assert_eq!(rank_subset(selection), rank)
        });
    }
    #[test]
    fn cached_prefix_keys_match_independent_complete_hashes() {
        let pool = Pool::new(0);
        let mut keys = vec![];
        pool.row_keys(|key, rank| {
            assert_eq!(keys.len(), rank);
            keys.push(key);
        });
        subsets(N, |selected, rank| {
            assert_eq!(
                keys[rank],
                pool.row_key(selected, &pool.secret_tuple(selected))
            )
        });
    }
}
