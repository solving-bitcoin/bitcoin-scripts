//! Threshold-complement delivery of one garbled label per candidate.
//! Conditional honest-setup bridge only: encrypted shares are NOT publicly
//! verified. Does not repair point-lock extraction or implement a verifier GC.
//! Every secret is a deterministic PUBLIC research fixture.
//! Separate 5-of-54 snapshot preserves the historical 4-of-50 benchmark source.
#[path = "round_major_composed.rs"]
pub(crate) mod composed;
use bitcoin::{
    hashes::{hash160, sha256, Hash},
    secp256k1::{ecdsa::Signature, PublicKey, Secp256k1, SecretKey},
};
#[path = "../pointlock_membership_decoder.rs"]
mod decoder;

const N: usize = 54;
const T: usize = 5;
const POOLS: usize = 95;
const DOMAIN: &str = "bitcoin-lab/round-major-complement/v1/public-test-fixture";
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
                    format!("round-major-publication-v1-{id}-{i}-{attempt}").as_bytes(),
                )
                .to_byte_array();
                let point =
                    PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&secret).unwrap())
                        .serialize();
                if point[1] == 0 || point[1] >= 128 {
                    continue;
                }
                let mut compact = [0u8; 64];
                compact[..32].copy_from_slice(&point[1..]);
                compact[63] = 1;
                let mut tau = Signature::from_compact(&compact)
                    .unwrap()
                    .serialize_der()
                    .to_vec();
                tau.push(1);
                if hash160::Hash::hash(&tau).to_byte_array()[0] == 0x30 {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn inverses() -> Vec<u128> {
        (0..64).map(|x| if x == 0 { 0 } else { inv(x) }).collect()
    }

    #[test]
    fn all_five_of_eight_openings_produce_exact_labels_and_lexicographic_rank() {
        let pool = Pool::new(0, 8);
        let table = pool.generate();
        let gc = decoder::build(0, &pool.labels, T, pool.private_garbling_seed);
        let inverses = inverses();
        let mut choices: Vec<Selection> = (0u16..256)
            .filter(|mask| mask.count_ones() == T as u32)
            .map(|mask| {
                (0..8)
                    .filter(|i| mask >> i & 1 == 1)
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap()
            })
            .collect();
        choices.sort();
        assert_eq!(choices.len(), 56);
        for (rank, selected) in choices.iter().copied().enumerate() {
            let labels = pool
                .open(selected, &pool.secret_tuple(selected), &table, &inverses)
                .unwrap();
            for i in 0..8 {
                assert_eq!(
                    labels[i],
                    pool.labels[i][usize::from(selected.contains(&i))]
                );
            }
            assert_eq!(
                gc.decode_outputs(&gc.evaluate(&labels).unwrap()),
                Some((rank, true))
            );
        }
        // The rank predicate rejects every other cardinality, including >5.
        for mask in 0u16..256 {
            let labels: Vec<_> = (0..8)
                .map(|i| pool.labels[i][(mask >> i & 1) as usize])
                .collect();
            assert_eq!(
                gc.decode_outputs(&gc.evaluate(&labels).unwrap()).unwrap().1,
                mask.count_ones() == 5
            );
        }
    }

    #[test]
    fn full_pool_boundary_choices_and_hostile_openings() {
        let pool = Pool::new(2, N);
        let table = pool.generate();
        let gc = decoder::build(2, &pool.labels, T, pool.private_garbling_seed);
        let inverses = inverses();
        for selected in [[0, 1, 2, 3, 4], [49, 50, 51, 52, 53], [0, 7, 23, 41, 53]] {
            let labels = pool
                .open(selected, &pool.secret_tuple(selected), &table, &inverses)
                .unwrap();
            assert_eq!(
                gc.decode_outputs(&gc.evaluate(&labels).unwrap()),
                Some((rank(selected), true))
            );
        }
        let selected = [0, 1, 2, 3, 4];
        let secrets = pool.secret_tuple(selected);
        for bad in [[0, 1, 2, 3, 3], [1, 0, 2, 3, 4], [0, 1, 2, 3, 54]] {
            assert!(pool.open(bad, &secrets, &table, &inverses).is_none());
        }
        let mut bad_secret = secrets;
        bad_secret[0] = pool.secrets[5];
        assert!(pool
            .open(selected, &bad_secret, &table, &inverses)
            .is_none());
        assert!(pool
            .open(selected, &secrets, &table[..table.len() - 1], &inverses)
            .is_none());
        let mut corrupted = table.clone();
        corrupted[offset(0, 5, N)] ^= 1;
        assert!(pool
            .open(selected, &secrets, &corrupted, &inverses)
            .is_none());
        assert!(!pool.check_opened(&corrupted));
        // Unchanged public commitments do not certify the encrypted table.
        // Another opening that avoids the changed sender row still succeeds.
        let other = [5, 6, 7, 8, 9];
        assert!(pool
            .open(other, &pool.secret_tuple(other), &corrupted, &inverses)
            .is_some());
    }
}
