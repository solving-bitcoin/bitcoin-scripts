//! Threshold-complement delivery of one garbled label per candidate.
//! Conditional honest-setup bridge only: encrypted shares are NOT publicly
//! verified. Does not repair point-lock extraction or implement a verifier GC.
//! Every secret is a deterministic PUBLIC research fixture.
#[path = "pointlock_decoders/composed.rs"]
pub(crate) mod composed;
use bitcoin::{
    hashes::{sha256, Hash},
    secp256k1::{PublicKey, Secp256k1, SecretKey},
};
use num_bigint::BigUint;
use serde_json::json;
use std::time::Instant;
#[path = "pointlock_membership_decoder.rs"]
mod decoder;

const N: usize = 50;
const T: usize = 4;
const POOLS: usize = 115;
const DOMAIN: &str = "bitcoin-lab/threshold-complement/v1/public-test-fixture";
type Selection = [usize; T];
type Label = u128;

// GF(2^128), polynomial X^128 + X^7 + X^2 + X + 1, little-endian basis.
fn mul(mut a: u128, mut b: u128) -> u128 {
    let mut out = 0;
    while b != 0 {
        if b & 1 != 0 {
            out ^= a;
        }
        let high = a >> 127;
        a <<= 1;
        if high != 0 {
            a ^= 0x87;
        }
        b >>= 1;
    }
    out
}
fn inv(a: u128) -> u128 {
    assert_ne!(a, 0);
    let mut y = a;
    for _ in 0..126 {
        y = mul(mul(y, y), a);
    }
    mul(y, y)
}
fn evaluate(coefficients: &[u128], x: u128) -> u128 {
    coefficients.iter().rev().fold(0, |y, a| mul(y, x) ^ a)
}
fn weights(selected: Selection, inverses: &[u128]) -> [u128; T] {
    std::array::from_fn(|i| {
        (0..T).filter(|&j| i != j).fold(1, |v, j| {
            let xi = selected[i] + 1;
            let xj = selected[j] + 1;
            mul(mul(v, xj as u128), inverses[xi ^ xj])
        })
    })
}
fn fixture(domain: &[u8], id: usize, a: usize, b: usize) -> u128 {
    let mut h = blake3::Hasher::new_derive_key(DOMAIN);
    h.update(domain);
    for v in [id, a, b] {
        h.update(&(v as u64).to_le_bytes());
    }
    u128::from_le_bytes(h.finalize().as_bytes()[..16].try_into().unwrap())
}
fn one_label(id: usize, index: usize, secret: &[u8; 32]) -> Label {
    let mut h = blake3::Hasher::new_derive_key(DOMAIN);
    h.update(b"one-label");
    h.update(&(id as u64).to_le_bytes());
    h.update(&(index as u64).to_le_bytes());
    h.update(secret);
    u128::from_le_bytes(h.finalize().as_bytes()[..16].try_into().unwrap())
}
fn masks(id: usize, sender: usize, secret: &[u8; 32], n: usize) -> Vec<u128> {
    let mut h = blake3::Hasher::new_keyed(secret);
    h.update(DOMAIN.as_bytes());
    h.update(b"encrypted-complement-shares");
    h.update(&(id as u64).to_le_bytes());
    h.update(&(sender as u64).to_le_bytes());
    let mut bytes = vec![0; n * 16];
    h.finalize_xof().fill(&mut bytes);
    bytes
        .chunks_exact(16)
        .map(|b| u128::from_le_bytes(b.try_into().unwrap()))
        .collect()
}
fn commitment(label: Label) -> [u8; 32] {
    *blake3::hash(&label.to_le_bytes()).as_bytes()
}
fn offset(sender: usize, recipient: usize, n: usize) -> usize {
    assert_ne!(sender, recipient);
    sender * (n - 1) + recipient - usize::from(recipient > sender)
}
struct Pool {
    id: usize,
    secrets: Vec<[u8; 32]>,
    points: Vec<[u8; 33]>,
    labels: Vec<[Label; 2]>,
    commitments: Vec<[[u8; 32]; 2]>,
    polynomials: Vec<[u128; T]>,
    private_garbling_seed: [u8; 32],
}
impl Pool {
    fn new(id: usize, n: usize) -> Self {
        let secp = Secp256k1::new();
        let mut secrets = vec![];
        let mut points = vec![];
        for i in 0..n {
            for attempt in 0.. {
                let secret = sha256::Hash::hash(
                    format!("anchored-publication-v1-{id}-{i}-{attempt}").as_bytes(),
                )
                .to_byte_array();
                let point =
                    PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&secret).unwrap())
                        .serialize();
                if point[1] == 0 || point[1] >= 128 {
                    continue;
                }
                secrets.push(secret);
                points.push(point);
                break;
            }
        }
        let delta = fixture(b"global-free-xor-delta", 0, 0, 0) | 1;
        let labels: Vec<_> = secrets
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let one = one_label(id, i, s);
                [one ^ delta, one]
            })
            .collect();
        let polynomials = labels
            .iter()
            .enumerate()
            .map(|(j, l)| {
                std::array::from_fn(|k| {
                    if k == 0 {
                        l[0]
                    } else {
                        fixture(b"polynomial", id, j, k)
                    }
                })
            })
            .collect();
        let commitments = labels.iter().map(|p| p.map(commitment)).collect();
        let mut private_garbling_seed = [0; 32];
        private_garbling_seed[..16]
            .copy_from_slice(&fixture(b"private-garbling-seed", id, 0, 0).to_le_bytes());
        private_garbling_seed[16..]
            .copy_from_slice(&fixture(b"private-garbling-seed", id, 0, 1).to_le_bytes());
        Self {
            id,
            secrets,
            points,
            labels,
            commitments,
            polynomials,
            private_garbling_seed,
        }
    }
    fn generate(&self) -> Vec<u128> {
        let n = self.secrets.len();
        let mut out = vec![0; n * (n - 1)];
        for i in 0..n {
            let pads = masks(self.id, i, &self.secrets[i], n);
            for j in 0..n {
                if i != j {
                    out[offset(i, j, n)] =
                        evaluate(&self.polynomials[j], (i + 1) as u128) ^ pads[j];
                }
            }
        }
        out
    }
    fn check_opened(&self, table: &[u128]) -> bool {
        // Requires EVERY scalar, EVERY polynomial coefficient and both labels.
        // This is explicitly not a public setup check.
        let secp = Secp256k1::new();
        for i in 0..self.secrets.len() {
            let one = one_label(self.id, i, &self.secrets[i]);
            if one != self.labels[i][1]
                || self.polynomials[i][0] != self.labels[i][0]
                || self.labels[i].map(commitment) != self.commitments[i]
                || PublicKey::from_secret_key(
                    &secp,
                    &SecretKey::from_slice(&self.secrets[i]).unwrap(),
                )
                .serialize()
                    != self.points[i]
            {
                return false;
            }
        }
        self.generate() == table
    }
    fn open(
        &self,
        selected: Selection,
        secrets: &[[u8; 32]; T],
        table: &[u128],
        inverses: &[u128],
    ) -> Option<Vec<Label>> {
        PublicView {
            id: self.id,
            points: &self.points,
            commitments: &self.commitments,
        }
        .open(selected, secrets, table, inverses)
    }
    fn secret_tuple(&self, selected: Selection) -> [[u8; 32]; T] {
        selected.map(|i| self.secrets[i])
    }
}
// The opening algorithm has access to this public view only. The benchmark
// retains a separate Pool with all secrets to audit correctness.
struct PublicView<'a> {
    id: usize,
    points: &'a [[u8; 33]],
    commitments: &'a [[[u8; 32]; 2]],
}
impl PublicView<'_> {
    fn open(
        &self,
        selected: Selection,
        secrets: &[[u8; 32]; T],
        table: &[u128],
        inverses: &[u128],
    ) -> Option<Vec<Label>> {
        let n = self.points.len();
        if selected[T - 1] >= n
            || !selected.windows(2).all(|w| w[0] < w[1])
            || table.len() != n * (n - 1)
        {
            return None;
        }
        let secp = Secp256k1::new();
        for k in 0..T {
            let key = SecretKey::from_slice(&secrets[k]).ok()?;
            if PublicKey::from_secret_key(&secp, &key).serialize() != self.points[selected[k]] {
                return None;
            }
        }
        let pads: Vec<_> = (0..T)
            .map(|k| masks(self.id, selected[k], &secrets[k], n))
            .collect();
        let lambda = weights(selected, inverses);
        let mut out = vec![];
        for j in 0..n {
            let (bit, label) = if let Some(k) = selected.iter().position(|&i| i == j) {
                (1, one_label(self.id, j, &secrets[k]))
            } else {
                (
                    0,
                    (0..T).fold(0, |v, k| {
                        v ^ mul(lambda[k], table[offset(selected[k], j, n)] ^ pads[k][j])
                    }),
                )
            };
            if commitment(label) != self.commitments[j][bit] {
                return None;
            }
            out.push(label);
        }
        Some(out)
    }
}
fn choose(n: usize, k: usize) -> usize {
    if k > n {
        return 0;
    }
    (0..k.min(n - k)).fold(1, |v, j| v * (n - j) / (j + 1))
}
fn rank(selected: Selection) -> usize {
    let mut rank = 0;
    let mut start = 0;
    for (j, &index) in selected.iter().enumerate() {
        for skipped in start..index {
            rank += choose(N - skipped - 1, T - j - 1);
        }
        start = index + 1;
    }
    rank
}
fn parallel<TV: Send>(n: usize, workers: usize, job: impl Fn(usize) -> TV + Sync) -> Vec<TV> {
    std::thread::scope(|scope| {
        let job = &job;
        let hs: Vec<_> = (0..workers)
            .map(|w| {
                scope.spawn(move || {
                    (w..n)
                        .step_by(workers)
                        .map(|i| (i, job(i)))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        let mut v: Vec<_> = hs.into_iter().flat_map(|h| h.join().unwrap()).collect();
        v.sort_by_key(|x| x.0);
        v.into_iter().map(|x| x.1).collect()
    })
}
fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn native_check(
    pools: &[Pool],
    tables: &[Vec<u128>],
    decoders: &[decoder::Decoder],
    inverses: &[u128],
    report: &serde_json::Value,
) -> serde_json::Value {
    let records = report["recovery"]["extractions"].as_array().unwrap();
    assert_eq!(records.len(), POOLS * T);
    let mut value = BigUint::from(0u8);
    let mut factor = BigUint::from(1u8);
    for i in 0..POOLS {
        let mut rs: Vec<_> = records
            .iter()
            .filter(|r| r["pool"].as_u64() == Some(i as u64))
            .collect();
        rs.sort_by_key(|r| r["label"].as_u64().unwrap());
        assert_eq!(rs.len(), T);
        let selected = std::array::from_fn(|k| rs[k]["label"].as_u64().unwrap() as usize);
        let secrets =
            std::array::from_fn(|k| unhex(rs[k]["scalar"].as_str().unwrap()).try_into().unwrap());
        for k in 0..T {
            assert_eq!(
                pools[i].points[selected[k]].to_vec(),
                unhex(rs[k]["target"].as_str().unwrap())
            );
        }
        let labels = pools[i]
            .open(selected, &secrets, &tables[i], inverses)
            .unwrap();
        // Compare real secret labels, not merely public indices.
        for j in 0..N {
            assert_eq!(
                labels[j],
                pools[i].labels[j][usize::from(selected.contains(&j))]
            );
        }
        let outputs = decoders[i].evaluate(&labels).unwrap();
        let (decoded_rank, valid) = decoders[i].decode_outputs(&outputs).unwrap();
        assert!(valid);
        assert_eq!(decoded_rank, rank(selected));
        value += &factor * decoded_rank;
        factor *= choose(N, T);
    }
    assert_eq!(
        value,
        BigUint::from_bytes_be(&unhex(report["recovery"]["payload_hex"].as_str().unwrap()))
    );
    json!({"scope":"Cached Core extraction records and actual garbled per-pool membership-to-rank evaluation; no new Core run or complete garbled verifier.","scalar_openings":POOLS*T,"membership_wire_labels":POOLS*N,"one_labels":POOLS*T,"zero_labels":POOLS*(N-T),"garbled_rank_output_labels":POOLS*19,"payload_matches":true,"publication_vbytes":report["combined_vbytes"]})
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    let arg = |s: &str, d| {
        args.iter()
            .position(|v| v == s)
            .map_or(d, |i| args[i + 1].parse::<usize>().unwrap())
    };
    let count = arg("--pools", 1).clamp(1, POOLS);
    let workers = arg("--workers", 1).clamp(1, count);
    let samples = arg("--samples", 1).max(1);
    let native = args.iter().position(|v| v == "--native-recovery").map(|i| {
        let bytes = std::fs::read(&args[i + 1]).unwrap();
        (
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
            sha256::Hash::hash(&bytes).to_string(),
        )
    });
    let mut rows = vec![];
    let mut native_result = serde_json::Value::Null;
    for _ in 0..samples {
        let start = Instant::now();
        // Rebuild all interpolation preparation each sample; no free cache.
        let inverses: Vec<_> = (0..64).map(|x| if x == 0 { 0 } else { inv(x) }).collect();
        let pools = parallel(count, workers, |i| Pool::new(i, N));
        let preparation_ms = start.elapsed().as_secs_f64() * 1000.;
        let start = Instant::now();
        let tables = parallel(count, workers, |i| pools[i].generate());
        let table_generation_ms = start.elapsed().as_secs_f64() * 1000.;
        let start = Instant::now();
        let decoders = parallel(count, workers, |i| {
            decoder::build(i, &pools[i].labels, T, pools[i].private_garbling_seed)
        });
        let decoder_generation_ms = start.elapsed().as_secs_f64() * 1000.;
        let start = Instant::now();
        let checked = parallel(count, workers, |i| pools[i].check_opened(&tables[i]));
        assert!(checked.into_iter().all(|x| x));
        let decoder_checks = parallel(count, workers, |i| {
            decoders[i].same_tables(&decoder::build(
                i,
                &pools[i].labels,
                T,
                pools[i].private_garbling_seed,
            ))
        });
        assert!(decoder_checks.into_iter().all(|x| x));
        let opened_audit_ms = start.elapsed().as_secs_f64() * 1000.;
        let start = Instant::now();
        for i in 0..count {
            for selected in [[0, 1, 2, 3], [46, 47, 48, 49]] {
                let out = pools[i]
                    .open(
                        selected,
                        &pools[i].secret_tuple(selected),
                        &tables[i],
                        &inverses,
                    )
                    .unwrap();
                for j in 0..N {
                    assert_eq!(
                        out[j],
                        pools[i].labels[j][usize::from(selected.contains(&j))]
                    );
                }
                assert_eq!(
                    decoders[i].decode_outputs(&decoders[i].evaluate(&out).unwrap()),
                    Some((rank(selected), true))
                );
            }
        }
        let selected_opening_check_ms = start.elapsed().as_secs_f64() * 1000.;
        if let Some((report, _)) = &native {
            assert_eq!(count, POOLS);
            native_result = native_check(&pools, &tables, &decoders, &inverses, report);
        }
        let mut decoder_digest = blake3::Hasher::new();
        for d in &decoders {
            decoder_digest.update(&d.fingerprint());
        }
        let mut h = blake3::Hasher::new();
        for table in &tables {
            for item in table {
                h.update(&item.to_le_bytes());
            }
        }
        rows.push(json!({"preparation_ms":preparation_ms,"table_generation_ms":table_generation_ms,"opened_audit_ms":opened_audit_ms,
            "decoder_generation_ms":decoder_generation_ms,
            "generation_ms":preparation_ms+table_generation_ms+decoder_generation_ms,"generation_plus_opened_audit_ms":preparation_ms+table_generation_ms+decoder_generation_ms+opened_audit_ms,
            "decoder_and_gates":decoders.iter().map(|d|d.counts().0).sum::<usize>(),"decoder_xor_gates":decoders.iter().map(|d|d.counts().1).sum::<usize>(),"decoder_garbled_bytes":decoders.iter().map(|d|d.counts().2).sum::<usize>(),
            "selected_opening_check_ms":selected_opening_check_ms,"decoder_digest_blake3":decoder_digest.finalize().to_hex().to_string(),"table_digest_blake3":h.finalize().to_hex().to_string()}));
    }
    println!("{}",serde_json::to_string_pretty(&json!({"evidence":"locally-reproduced","deployment":"unclassified",
        "scope":"Complete threshold-complement tables retained in RAM, all target scalar/point generation, label commitments, coefficients, field preparation and worker startup. Opened audit has every secret. Includes garbled per-pool membership-to-rank decoders. Excludes public setup verification (missing), complete mixed-radix decoder/garbled verifier, multiple cut-and-choose instances, point-lock scripts/transactions, process startup and compilation.",
        "security_status":"Conditional honest-setup label delivery only; encrypted-share binding under malicious setup remains missing. No new point-lock extraction claim.",
        "pools":count,"n":N,"t":T,"workers":workers,"build_profile":if cfg!(debug_assertions){"debug"}else{"release"},
        "encrypted_share_count":count*N*(N-1),"encrypted_share_bytes":count*N*(N-1)*16,
        "label_commitment_bytes":count*N*2*32,"target_point_bytes":count*N*33,"one_label_per_membership_wire":true,
        "public_setup_verification_ms":serde_json::Value::Null,"native_recovery_report_sha256":native.as_ref().map(|x|&x.1),"native_recovery_check":native_result,"samples":rows})).unwrap());
}
#[cfg(test)]
mod tests {
    use super::*;
    fn inverses() -> Vec<u128> {
        (0..64).map(|x| if x == 0 { 0 } else { inv(x) }).collect()
    }
    #[test]
    fn field_and_interpolation_boundaries() {
        for x in [1, 2, 3, 63, 1 << 127, u128::MAX, 0xabcdef123456789] {
            assert_eq!(mul(x, inv(x)), 1);
        }
        assert_eq!(mul(1 << 127, 2), 0x87);
        let coeffs = [0xdeadbeef, 1 << 127, u128::MAX, 0xabcdef];
        for s in [[0, 1, 2, 3], [1, 8, 27, 49], [46, 47, 48, 49]] {
            let l = weights(s, &inverses());
            assert_eq!(
                (0..T).fold(0, |v, k| v ^ mul(
                    l[k],
                    evaluate(&coeffs, (s[k] + 1) as u128)
                )),
                coeffs[0]
            );
        }
    }
    #[test]
    fn every_reduced_subset_gets_exact_selected_and_complement_labels() {
        let p = Pool::new(0, 8);
        let table = p.generate();
        let invs = inverses();
        let mut count = 0;
        for a in 0..5 {
            for b in a + 1..6 {
                for c in b + 1..7 {
                    for d in c + 1..8 {
                        let s = [a, b, c, d];
                        let got = p.open(s, &p.secret_tuple(s), &table, &invs).unwrap();
                        for j in 0..8 {
                            assert_eq!(got[j], p.labels[j][usize::from(s.contains(&j))]);
                        }
                        count += 1;
                    }
                }
            }
        }
        assert_eq!(count, choose(8, 4));
    }
    #[test]
    fn malformed_openings_and_used_ciphertext_changes_reject() {
        let p = Pool::new(0, 8);
        let table = p.generate();
        let invs = inverses();
        let s = [0, 1, 2, 3];
        let secrets = p.secret_tuple(s);
        for bad in [[0, 1, 2, 2], [1, 0, 2, 3], [0, 1, 2, 8]] {
            assert!(p.open(bad, &secrets, &table, &invs).is_none());
        }
        let mut wrong = secrets;
        wrong[0] = p.secrets[4];
        assert!(p.open(s, &wrong, &table, &invs).is_none());
        assert!(p
            .open(s, &secrets, &table[..table.len() - 1], &invs)
            .is_none());
        let mut bad = table.clone();
        bad[offset(0, 4, 8)] ^= 1;
        assert!(p.open(s, &secrets, &bad, &invs).is_none());
        assert!(!p.check_opened(&bad));
        assert!(Pool::new(1, 8).open(s, &secrets, &table, &invs).is_none());
    }
    #[test]
    fn fewer_than_threshold_shares_leave_any_constant_possible() {
        let p = Pool::new(0, 8);
        let s = [0, 2, 4, 6];
        for &j in &s {
            // h vanishes at every disclosed share for this selected j.
            let mut h = vec![1u128];
            for &i in &s {
                if i != j {
                    let mut next = vec![0; h.len() + 1];
                    for k in 0..h.len() {
                        next[k] ^= mul(h[k], (i + 1) as u128);
                        next[k + 1] ^= h[k];
                    }
                    h = next;
                }
            }
            for desired in [0, 1, u128::MAX, p.polynomials[j][0] ^ 0x12345] {
                let scale = mul(desired ^ p.polynomials[j][0], inv(h[0]));
                let other: Vec<_> = (0..T)
                    .map(|k| p.polynomials[j][k] ^ mul(scale, h[k]))
                    .collect();
                assert_eq!(other[0], desired);
                for &i in &s {
                    if i != j {
                        assert_eq!(
                            evaluate(&other, (i + 1) as u128),
                            evaluate(&p.polynomials[j], (i + 1) as u128)
                        );
                    }
                }
            }
        }
        // This algebra test excludes public label hashes and encrypted shares;
        // their security additionally needs preimage/PRF assumptions.
    }
    #[test]
    fn retaining_diagonal_share_would_reveal_free_xor_delta() {
        let p = Pool::new(0, 8);
        let s = [0, 1, 2, 3];
        let w = weights(s, &inverses());
        let zero = (0..T).fold(0, |v, k| {
            v ^ mul(w[k], evaluate(&p.polynomials[0], (s[k] + 1) as u128))
        });
        let delta = zero ^ one_label(0, 0, &p.secrets[0]);
        for j in 0..8 {
            assert_eq!(p.labels[j][0] ^ delta, p.labels[j][1]);
        }
    }
    #[test]
    fn malicious_table_passes_public_shape_but_can_fail_later_opening() {
        let p = Pool::new(0, 8);
        let good = p.generate();
        let mut bad = good.clone();
        bad[offset(0, 4, 8)] ^= 1;
        // All points, public label hashes, lengths and all unopened entries are
        // unchanged. These public data do not certify encrypted-share contents.
        assert_eq!(good.len(), bad.len());
        assert!(p
            .open(
                [0, 1, 2, 3],
                &p.secret_tuple([0, 1, 2, 3]),
                &bad,
                &inverses()
            )
            .is_none());
        // A disjoint honest opening does not test the corrupted sender row.
        assert!(p
            .open(
                [4, 5, 6, 7],
                &p.secret_tuple([4, 5, 6, 7]),
                &bad,
                &inverses()
            )
            .is_some());
    }
}
