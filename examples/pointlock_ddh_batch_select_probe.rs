//! Offchain DDH batch-select experiment. NOT a Bitcoin point lock.
//! Public deterministic fixtures; no production randomness or security claim.
//! Native binding of the message-dependent aggregate key and public setup
//! verification of ciphertexts remain missing. An opened audit is NOT public.
use bitcoin::{
    hashes::{sha256, Hash},
    secp256k1::{All, PublicKey, Scalar, Secp256k1, SecretKey},
};
use num_bigint::BigUint;
use serde_json::json;
use std::{sync::OnceLock, time::Instant};

type Point = Option<PublicKey>;
type Label = [u8; 16];
type Field = [u8; 32];
const DOMAIN: &str = "bitcoin-lab/ddh-batch-select/v1/PUBLIC-FIXTURE";
#[cfg(test)]
#[path = "pointlock_membership_decoder.rs"]
mod decoder;
fn order() -> &'static BigUint {
    static N: OnceLock<BigUint> = OnceLock::new();
    N.get_or_init(|| {
        BigUint::parse_bytes(
            b"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
            16,
        )
        .unwrap()
    })
}
fn field(x: BigUint) -> Field {
    let bytes = (x % order()).to_bytes_be();
    let mut out = [0; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}
fn sum(a: Field, b: Field) -> Field {
    field(BigUint::from_bytes_be(&a) + BigUint::from_bytes_be(&b))
}
fn product(a: Field, b: Field) -> Field {
    field(BigUint::from_bytes_be(&a) * BigUint::from_bytes_be(&b))
}
fn fixture(id: usize, role: &str, i: usize) -> Field {
    let h = sha256::Hash::hash(format!("{DOMAIN}/{id}/{role}/{i}").as_bytes()).to_byte_array();
    field(BigUint::from_bytes_be(&h) % (order() - 1u8) + 1u8)
}
fn base(secp: &Secp256k1<All>, s: Field) -> Point {
    if s == [0; 32] {
        None
    } else {
        Some(PublicKey::from_secret_key(
            secp,
            &SecretKey::from_slice(&s).unwrap(),
        ))
    }
}
fn add(a: Point, b: Point) -> Point {
    match (a, b) {
        (None, p) | (p, None) => p,
        (Some(a), Some(b)) => a.combine(&b).ok(),
    }
}
fn neg(secp: &Secp256k1<All>, p: Point) -> Point {
    p.map(|p| p.negate(secp))
}
fn mul(secp: &Secp256k1<All>, p: Point, s: Field) -> Point {
    if s == [0; 32] {
        None
    } else {
        p.map(|p| {
            p.mul_tweak(secp, &Scalar::from_be_bytes(s).unwrap())
                .unwrap()
        })
    }
}
fn serialize(p: Point) -> [u8; 33] {
    p.map(|p| p.serialize()).unwrap_or([0; 33])
}
fn digest(label: Label) -> [u8; 32] {
    sha256::Hash::hash(&label).to_byte_array()
}

// Reversible 128-bit label -> even-Y point, with a 16-bit counter.
// Failure is explicit, not an assertion that every label necessarily embeds.
fn embed(label: Label) -> Result<Point, &'static str> {
    let mut bytes = [0; 33];
    bytes[0] = 2;
    bytes[15..31].copy_from_slice(&label);
    for counter in 0u32..=65535 {
        bytes[31..].copy_from_slice(&(counter as u16).to_be_bytes());
        if let Ok(p) = PublicKey::from_slice(&bytes) {
            return Ok(Some(p));
        }
    }
    Err("label embedding exhausted its counter")
}
fn unembed(p: Point) -> Option<Label> {
    let bytes = p?.serialize();
    if bytes[0] != 2 || bytes[1..15].iter().any(|&v| v != 0) {
        return None;
    }
    let label = bytes[15..31].try_into().ok()?;
    if embed(label).ok()? != p {
        return None;
    }
    Some(label)
}

#[derive(Clone)]
struct Public {
    id: usize,
    key_points: Vec<Point>, // K0 and one coefficient point per message bit
    bases: Vec<Point>,
    offset: Vec<Point>,
    matrix: Vec<Vec<Point>>,
    label_hashes: Vec<[[u8; 32]; 2]>,
}
struct Private {
    keys: Vec<Field>,
    randomizers: Vec<Field>,
    labels: Vec<[Label; 2]>,
}
fn prepare(
    secp: &Secp256k1<All>,
    id: usize,
    width: usize,
) -> Result<(Public, Private), &'static str> {
    let keys: Vec<_> = (0..=width).map(|i| fixture(id, "key", i)).collect();
    let randomizers: Vec<_> = (0..width)
        .map(|i| fixture(id, "row-randomizer", i))
        .collect();
    let mut delta: Label = fixture(0, "free-XOR-offset", 0)[..16].try_into().unwrap();
    delta[15] |= 1;
    let labels: Vec<[Label; 2]> = (0..width)
        .map(|i| {
            let zero: Label = fixture(id, "zero-label", i)[..16].try_into().unwrap();
            let one = std::array::from_fn(|j| zero[j] ^ delta[j]);
            [zero, one]
        })
        .collect();
    let encoded: Vec<[Point; 2]> = labels
        .iter()
        .map(|l| Ok([embed(l[0])?, embed(l[1])?]))
        .collect::<Result<_, &'static str>>()?;
    let offset = (0..width)
        .map(|i| add(encoded[i][0], base(secp, product(randomizers[i], keys[0]))))
        .collect();
    let matrix = (0..width)
        .map(|i| {
            (0..width)
                .map(|j| {
                    let pad = base(secp, product(randomizers[i], keys[j + 1]));
                    if i == j {
                        add(pad, add(encoded[i][1], neg(secp, encoded[i][0])))
                    } else {
                        pad
                    }
                })
                .collect()
        })
        .collect();
    Ok((
        Public {
            id,
            key_points: keys.iter().map(|&k| base(secp, k)).collect(),
            bases: randomizers.iter().map(|&r| base(secp, r)).collect(),
            offset,
            matrix,
            label_hashes: labels
                .iter()
                .map(|l| [digest(l[0]), digest(l[1])])
                .collect(),
        },
        Private {
            keys,
            randomizers,
            labels,
        },
    ))
}
fn shape(p: &Public) -> bool {
    let n = p.bases.len();
    n > 0
        && p.key_points.len() == n + 1
        && p.offset.len() == n
        && p.matrix.len() == n
        && p.label_hashes.len() == n
        && p.matrix.iter().all(|r| r.len() == n)
        && p.bases.iter().chain(&p.key_points).all(Option::is_some)
}
fn opened_audit(secp: &Secp256k1<All>, p: &Public, s: &Private) -> bool {
    // Independent variable-base recomputation using secrets. This is NOT the
    // public setup check required by the research goal.
    if !shape(p)
        || s.keys.len() != p.key_points.len()
        || s.randomizers.len() != p.bases.len()
        || s.labels.len() != p.bases.len()
    {
        return false;
    }
    for (i, &k) in s.keys.iter().enumerate() {
        if base(secp, k) != p.key_points[i] {
            return false;
        }
    }
    for i in 0..p.bases.len() {
        if base(secp, s.randomizers[i]) != p.bases[i] {
            return false;
        }
        if p.label_hashes[i] != [digest(s.labels[i][0]), digest(s.labels[i][1])] {
            return false;
        }
        let [a, b] = [
            embed(s.labels[i][0]).unwrap(),
            embed(s.labels[i][1]).unwrap(),
        ];
        if p.offset[i] != add(a, mul(secp, p.bases[i], s.keys[0])) {
            return false;
        }
        for j in 0..p.bases.len() {
            let pad = mul(secp, p.bases[i], s.keys[j + 1]);
            let expected = if i == j {
                add(pad, add(b, neg(secp, a)))
            } else {
                pad
            };
            if p.matrix[i][j] != expected {
                return false;
            }
        }
    }
    true
}
fn key(s: &Private, bits: &[bool]) -> Field {
    assert_eq!(s.keys.len(), bits.len() + 1);
    bits.iter().enumerate().fold(
        s.keys[0],
        |k, (i, &b)| if b { sum(k, s.keys[i + 1]) } else { k },
    )
}
fn target(p: &Public, bits: &[bool]) -> Point {
    bits.iter().enumerate().fold(p.key_points[0], |t, (i, &b)| {
        if b {
            add(t, p.key_points[i + 1])
        } else {
            t
        }
    })
}
fn open(secp: &Secp256k1<All>, p: &Public, bits: &[bool], k: Field) -> Option<Vec<Label>> {
    if !shape(p) || bits.len() != p.bases.len() || BigUint::from_bytes_be(&k) >= *order() {
        return None;
    }
    // This is an OFFCHAIN group check, NOT a compiled Bitcoin predicate.
    if base(secp, k) != target(p, bits) {
        return None;
    }
    (0..bits.len())
        .map(|i| {
            let encrypted = bits.iter().enumerate().fold(p.offset[i], |c, (j, &b)| {
                if b {
                    add(c, p.matrix[i][j])
                } else {
                    c
                }
            });
            let label = unembed(add(encrypted, neg(secp, mul(secp, p.bases[i], k))))?;
            if digest(label) == p.label_hashes[i][usize::from(bits[i])] {
                Some(label)
            } else {
                None
            }
        })
        .collect()
}
fn fingerprint(p: &Public) -> [u8; 32] {
    let mut data = vec![];
    data.extend_from_slice(&(p.id as u64).to_le_bytes());
    data.extend_from_slice(&(p.bases.len() as u64).to_le_bytes());
    for q in p
        .key_points
        .iter()
        .chain(&p.bases)
        .chain(&p.offset)
        .chain(p.matrix.iter().flatten())
    {
        data.extend_from_slice(&serialize(*q));
    }
    for h in p.label_hashes.iter().flatten() {
        data.extend_from_slice(h);
    }
    sha256::Hash::hash(&data).to_byte_array()
}
fn parallel<T: Send, F: Fn(usize) -> T + Sync>(count: usize, workers: usize, f: F) -> Vec<T> {
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..workers.min(count))
            .map(|worker| {
                let f = &f;
                scope.spawn(move || {
                    (worker..count)
                        .step_by(workers.min(count))
                        .map(|i| (i, f(i)))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        let mut values: Vec<_> = handles
            .into_iter()
            .flat_map(|h| h.join().unwrap())
            .collect();
        values.sort_by_key(|v| v.0);
        values.into_iter().map(|v| v.1).collect()
    })
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    let parameter = |name: &str, fallback| {
        args.iter()
            .position(|s| s == name)
            .map(|i| args[i + 1].parse::<usize>().unwrap())
            .unwrap_or(fallback)
    };
    let width = parameter("--width", 32);
    let workers = parameter("--workers", 15);
    let samples = parameter("--samples", 5);
    assert!(width > 0 && 2048 % width == 0 && workers > 0 && samples > 0);
    let blocks = 2048 / width;
    let start = Instant::now();
    let secp = Secp256k1::new();
    let context_ms = start.elapsed().as_secs_f64() * 1000.;
    let mut rows = vec![];
    let mut expected_digest = None;
    for _ in 0..samples {
        let start = Instant::now();
        let prepared = parallel(blocks, workers, |id| prepare(&secp, id, width).unwrap());
        let generation_ms = start.elapsed().as_secs_f64() * 1000.;
        let start = Instant::now();
        assert!(parallel(blocks, workers, |id| opened_audit(
            &secp,
            &prepared[id].0,
            &prepared[id].1
        ))
        .iter()
        .all(|&v| v));
        let audit_ms = start.elapsed().as_secs_f64() * 1000.;
        let start = Instant::now();
        let openings = parallel(blocks, workers, |id| {
            let (p, s) = &prepared[id];
            for case in 0..4 {
                let bits: Vec<_> = (0..width)
                    .map(|i| match case {
                        0 => false,
                        1 => true,
                        2 => i % 2 == 0,
                        _ => fixture(id, "future-message", i)[0] & 1 != 0,
                    })
                    .collect();
                let got = open(&secp, p, &bits, key(s, &bits)).unwrap();
                assert_eq!(
                    got,
                    (0..width)
                        .map(|i| s.labels[i][usize::from(bits[i])])
                        .collect::<Vec<_>>()
                );
            }
            4 * width
        });
        assert_eq!(openings.iter().sum::<usize>(), 8192);
        let opening_four_messages_ms = start.elapsed().as_secs_f64() * 1000.;
        let mut fingerprints = vec![];
        for (p, _) in &prepared {
            fingerprints.extend_from_slice(&fingerprint(p));
        }
        let report_digest = sha256::Hash::hash(&fingerprints).to_string();
        if let Some(previous) = &expected_digest {
            assert_eq!(previous, &report_digest);
        }
        expected_digest = Some(report_digest);
        rows.push(
            json!({"generation_ms":generation_ms,"all_secrets_audit_ms":audit_ms,
            "generation_plus_all_secrets_audit_ms":generation_ms+audit_ms,
            "opening_four_messages_ms":opening_four_messages_ms}),
        );
    }
    let points = blocks * (width * width + 3 * width + 1);
    println!("{}", serde_json::to_string_pretty(&json!({
        "evidence":"locally-reproduced", "deployment":"unclassified",
        "scope":"Offchain batch-select only. No Bitcoin Script, transaction, native extraction, public setup check or complete garbled verifier.",
        "public_test_fixture_secrets":true, "message_bits":2048, "block_width":width, "blocks":blocks,
        "workers":workers,"context_initialization_ms":context_ms,
        "raw_opening_bytes":256+32*blocks,"compressed_scalar_keys":blocks,
        "public_group_elements":points,"public_group_element_bytes":33*points,
        "label_hash_bytes":2048*2*32,"public_payload_bytes":33*points+2048*2*32,
        "public_setup_verification_ms":serde_json::Value::Null,
        "public_fingerprint":expected_digest,"samples":rows,
        "exclusions":["public malicious-setup verification", "Bitcoin binding of kG=K0+sum(y_i*K_i)",
            "garbling of the BitVM3 verifier", "transaction generation and validation", "wire and file framing"],
        "provenance":{"source_sha256":sha256::Hash::hash(include_bytes!("pointlock_ddh_batch_select_probe.rs")).to_string(),
            "cargo_lock_sha256":sha256::Hash::hash(include_bytes!("../Cargo.lock")).to_string()}
    })).unwrap());
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_traits::Zero;
    #[test]
    fn delivered_labels_drive_existing_garbled_decoder() {
        let secp = Secp256k1::new();
        let (p, s) = prepare(&secp, 61, 8).unwrap();
        let pairs: Vec<_> = s
            .labels
            .iter()
            .map(|l| [u128::from_be_bytes(l[0]), u128::from_be_bytes(l[1])])
            .collect();
        let gc = decoder::build(61, &pairs, 4, fixture(61, "garbling-seed", 0));
        for mask in 0u16..256 {
            let bits: Vec<_> = (0..8).map(|i| mask & (1 << i) != 0).collect();
            let delivered = open(&secp, &p, &bits, key(&s, &bits)).unwrap();
            let labels: Vec<_> = delivered.into_iter().map(u128::from_be_bytes).collect();
            let (_, valid) = gc.decode_outputs(&gc.evaluate(&labels).unwrap()).unwrap();
            assert_eq!(valid, mask.count_ones() == 4);
        }
    }
    #[test]
    fn every_eight_bit_message_and_rebinding() {
        let secp = Secp256k1::new();
        let (p, s) = prepare(&secp, 31, 8).unwrap();
        assert!(opened_audit(&secp, &p, &s));
        for m in 0..256 {
            let bits: Vec<_> = (0..8).map(|i| m & (1 << i) != 0).collect();
            let k = key(&s, &bits);
            let got = open(&secp, &p, &bits, k).unwrap();
            assert_eq!(
                got,
                (0..8)
                    .map(|i| s.labels[i][usize::from(bits[i])])
                    .collect::<Vec<_>>()
            );
            let mut other = bits.clone();
            other[0] = !other[0];
            assert!(open(&secp, &p, &other, k).is_none());
            assert!(open(&secp, &p, &bits, sum(k, fixture(0, "wrong-key", 0))).is_none());
        }
    }
    #[test]
    fn malformed_table_passes_shape_and_aggregate_key_check() {
        let secp = Secp256k1::new();
        let (mut p, s) = prepare(&secp, 0, 8).unwrap();
        let keys_before = p.key_points.clone();
        let hashes_before = p.label_hashes.clone();
        p.matrix[0][0] = add(p.matrix[0][0], base(&secp, fixture(0, "bad-cell", 0)));
        assert!(shape(&p));
        assert_eq!(p.key_points, keys_before);
        assert_eq!(p.label_hashes, hashes_before);
        assert!(!opened_audit(&secp, &p, &s));
        let zeros = vec![false; 8];
        assert!(open(&secp, &p, &zeros, key(&s, &zeros)).is_some());
        let mut selected = zeros;
        selected[0] = true;
        let k = key(&s, &selected);
        assert_eq!(base(&secp, k), target(&p, &selected));
        assert!(open(&secp, &p, &selected, k).is_none());
    }
    #[test]
    fn disclosed_randomizer_reveals_both_labels() {
        let secp = Secp256k1::new();
        let (p, s) = prepare(&secp, 2, 8).unwrap();
        for i in 0..8 {
            let zero_point = add(
                p.offset[i],
                neg(&secp, mul(&secp, p.key_points[0], s.randomizers[i])),
            );
            let difference = add(
                p.matrix[i][i],
                neg(&secp, mul(&secp, p.key_points[i + 1], s.randomizers[i])),
            );
            assert_eq!(unembed(zero_point), Some(s.labels[i][0]));
            assert_eq!(unembed(add(zero_point, difference)), Some(s.labels[i][1]));
        }
    }
    #[test]
    fn public_relative_randomizers_reveal_alternatives_after_one_opening() {
        let secp = Secp256k1::new();
        let (p, s) = prepare(&secp, 3, 8).unwrap();
        // Counterfactual compression publishes r_i/r_j to derive rows from a
        // common base. Off-diagonal cells then expose each diagonal mask.
        let bits = vec![false; 8];
        let zeros = open(&secp, &p, &bits, key(&s, &bits)).unwrap();
        for i in 0..8 {
            let j = (i + 1) % 8;
            let inverse =
                BigUint::from_bytes_be(&s.randomizers[j]).modpow(&(order() - 2u8), order());
            let ratio = field(BigUint::from_bytes_be(&s.randomizers[i]) * inverse);
            let mask = mul(&secp, p.matrix[j][i], ratio);
            let difference = add(p.matrix[i][i], neg(&secp, mask));
            let other = unembed(add(embed(zeros[i]).unwrap(), difference));
            assert_eq!(other, Some(s.labels[i][1]));
        }
    }
    #[test]
    fn separate_threshold_shares_expose_the_free_xor_offset() {
        let secp = Secp256k1::new();
        let (p, s) = prepare(&secp, 5, 8).unwrap();
        let inverse_t = field(BigUint::from(4u8).modpow(&(order() - 2u8), order()));
        let a = product(s.keys[0], inverse_t);
        // x_i = k_i + a makes sum of any four x_i equal the batch-select key.
        // Even public point compatibility is satisfied by X_i = K_i + K0/4.
        let shares: Vec<_> = (0..8).map(|i| sum(s.keys[i + 1], a)).collect();
        for i in 0..8 {
            assert_eq!(
                base(&secp, shares[i]),
                add(p.key_points[i + 1], mul(&secp, p.key_points[0], inverse_t))
            );
        }
        let mut checked = 0;
        for mask in 0u16..256 {
            if mask.count_ones() != 4 {
                continue;
            }
            let bits: Vec<_> = (0..8).map(|i| mask & (1 << i) != 0).collect();
            let revealed: Vec<_> = (0..8)
                .filter(|&i| bits[i])
                .map(|i| (i, shares[i]))
                .collect();
            let k = revealed.iter().fold([0; 32], |k, (_, x)| sum(k, *x));
            let labels = open(&secp, &p, &bits, k).unwrap();
            // From here onward the attack uses only public data and this one
            // opening (no row randomizers, hidden coefficients or other shares).
            let (i, xi) = revealed[0];
            let (j, xj) = revealed[1];
            let difference_scalar =
                field(BigUint::from_bytes_be(&xi) + order() - BigUint::from_bytes_be(&xj));
            let mask_i = add(p.matrix[i][j], mul(&secp, p.bases[i], difference_scalar));
            let difference_labels = add(p.matrix[i][i], neg(&secp, mask_i));
            let zero = unembed(add(
                embed(labels[i]).unwrap(),
                neg(&secp, difference_labels),
            ))
            .unwrap();
            let delta: Label = std::array::from_fn(|b| zero[b] ^ labels[i][b]);
            let alternatives: Vec<Label> = labels
                .iter()
                .map(|l| std::array::from_fn(|b| l[b] ^ delta[b]))
                .collect();
            // Private fixtures only supply the independent expected result.
            for row in 0..8 {
                assert_eq!(alternatives[row], s.labels[row][usize::from(!bits[row])]);
            }
            checked += 1;
        }
        assert_eq!(checked, 70);
    }
    #[test]
    fn label_and_scalar_boundaries() {
        let secp = Secp256k1::new();
        for label in [[0; 16], [255; 16], [128; 16]] {
            assert_eq!(unembed(embed(label).unwrap()), Some(label));
        }
        assert!(unembed(None).is_none());
        assert_eq!(base(&secp, [0; 32]), None);
        let (p, s) = prepare(&secp, 4, 1).unwrap();
        assert!(open(&secp, &p, &[], [0; 32]).is_none());
        assert!(open(&secp, &p, &[false], [255; 32]).is_none());
        assert!(open(&secp, &p, &[false], key(&s, &[false])).is_some());
        assert!(BigUint::from_bytes_be(&field(order().clone())).is_zero());
    }
}
