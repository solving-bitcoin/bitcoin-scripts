//! README metric snapshots.
//!
//! Run with `UPDATE_PRIMITIVE_METRICS=1 cargo test --test primitive_metrics`
//! after intentionally changing a measured script. A normal test run fails if
//! a README still contains the old value.

use std::{env, fs, path::Path};

use bitcoin::consensus::encode::serialize;
use bitcoin::Witness;
use bitcoin_lab::{
    arithmetic::{bigint::U254, rns, u32, u4},
    ciphers::prince,
    curves::bn254::{
        fields::{fp254::Fp254Impl, fq::Fq, fq2::Fq2, fr::Fr},
        groups::{g1::G1Affine, g2::G2Affine},
    },
    hashes::{bithash, blake3, sha256},
    signatures::{hors, lamport, Wots, Wots32},
};
use bitcoin_script::script;

struct Metric {
    readme: &'static str,
    key: &'static str,
    value: usize,
}

fn script_len(script: bitcoin_script::Script) -> usize {
    script.compile().len()
}

fn witness_size(items: &[Vec<u8>]) -> usize {
    serialize(&Witness::from_slice(items)).len()
}

fn metrics() -> Vec<Metric> {
    let rns_add = script! {
        { rns::rns_push_add_tables() }
        { rns::rns_add() }
        { rns::rns_drop_add_tables() }
        { rns::rns_fromaltstack() }
    };
    let rns_sub = script! {
        { rns::rns_push_sub_tables() }
        { rns::rns_sub() }
        { rns::rns_drop_sub_tables() }
        { rns::rns_fromaltstack() }
    };
    let rns_mul = script! {
        { rns::rns_push_mul_tables() }
        { rns::rns_mul() }
        { rns::rns_drop_mul_tables() }
        { rns::rns_fromaltstack() }
    };

    let lamport_preimages: [&[u8]; 4] = [b"secret0", b"secret1", b"secret2", b"secret3"];
    let (h0, h1, h2, h3) = lamport::lamport_2bit_public_keys(
        lamport_preimages[0],
        lamport_preimages[1],
        lamport_preimages[2],
        lamport_preimages[3],
    );
    let lamport_witness = vec![vec![1], lamport_preimages[1].to_vec()];

    let hors_preimages = (0u8..32).map(|i| vec![i; 32]).collect::<Vec<_>>();
    let hors_public_keys = hors::hors_public_keys(&hors_preimages);
    let hors_witness = hors::hors_unlocking_witness(&hors_preimages, &(0..8).collect::<Vec<_>>());

    let wots_secret = vec![0x42; 20];
    let wots_message = [0u8; 32];
    let wots_public_key = Wots32::generate_public_key(&wots_secret);
    let wots_witness = Wots32::sign_to_raw_witness(&wots_secret, &wots_message);

    vec![
        Metric {
            readme: "src/arithmetic/u4/README.md",
            key: "u4_add_tables",
            value: script_len(u4::add::u4_push_add_tables()),
        },
        Metric {
            readme: "src/arithmetic/u32/README.md",
            key: "u32_add_drop",
            value: script_len(u32::add::u32_add_drop(0, 1)),
        },
        Metric {
            readme: "src/arithmetic/bigint/README.md",
            key: "u254_add",
            value: script_len(U254::add(1, 0)),
        },
        Metric {
            readme: "src/arithmetic/bigint/README.md",
            key: "u254_mul",
            value: script_len(U254::mul()),
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "rns_add",
            value: script_len(rns_add),
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "rns_sub",
            value: script_len(rns_sub),
        },
        Metric {
            readme: "src/arithmetic/rns/README.md",
            key: "rns_mul",
            value: script_len(rns_mul),
        },
        Metric {
            readme: "src/hashes/sha256/README.md",
            key: "sha2_u32_32",
            value: script_len(sha256::sha2_u32::sha256(32)),
        },
        Metric {
            readme: "src/hashes/sha256/README.md",
            key: "sha2_u4_32",
            value: script_len(sha256::sha2_u4::sha256(32)),
        },
        Metric {
            readme: "src/hashes/blake3/README.md",
            key: "blake3_64_limb29",
            value: blake3::blake3_compute_script_with_limb(64, 29)
                .compile()
                .len(),
        },
        Metric {
            readme: "src/hashes/bithash/README.md",
            key: "bithash_verify",
            value: script_len(bithash::bithash_verify([0; 20])),
        },
        Metric {
            readme: "src/signatures/lamport/README.md",
            key: "lamport_lock",
            value: script_len(lamport::lamport_2bit_commit(h0, h1, h2, h3)),
        },
        Metric {
            readme: "src/signatures/lamport/README.md",
            key: "lamport_witness",
            value: witness_size(&lamport_witness),
        },
        Metric {
            readme: "src/signatures/hors/README.md",
            key: "hors_lock_n32_t8",
            value: script_len(hors::hors_locking_script(&hors_public_keys, 8)),
        },
        Metric {
            readme: "src/signatures/hors/README.md",
            key: "hors_witness_n32_t8",
            value: witness_size(&hors_witness),
        },
        Metric {
            readme: "src/signatures/winternitz/README.md",
            key: "wots32_lock",
            value: script_len(Wots32::checksig_verify(&wots_public_key)),
        },
        Metric {
            readme: "src/signatures/winternitz/README.md",
            key: "wots32_witness",
            value: serialize(&wots_witness).len(),
        },
        Metric {
            readme: "src/ciphers/prince/README.md",
            key: "prince_encrypt",
            value: script_len(prince::prince_encrypt(0)),
        },
        Metric {
            readme: "src/ciphers/prince/README.md",
            key: "prince_witness_min",
            value: witness_size(&vec![Vec::new(); 16]),
        },
        Metric {
            readme: "src/ciphers/prince/README.md",
            key: "prince_witness_max",
            value: witness_size(&vec![vec![1]; 16]),
        },
        Metric {
            readme: "src/curves/bn254/fields/README.md",
            key: "fq_add",
            value: script_len(Fq::add(1, 0)),
        },
        Metric {
            readme: "src/curves/bn254/fields/README.md",
            key: "fr_add",
            value: script_len(Fr::add(1, 0)),
        },
        Metric {
            readme: "src/curves/bn254/fields/README.md",
            key: "fq2_add",
            value: script_len(Fq2::add(2, 0)),
        },
        Metric {
            readme: "src/curves/bn254/groups/README.md",
            key: "g1_is_zero",
            value: script_len(G1Affine::is_zero()),
        },
        Metric {
            readme: "src/curves/bn254/groups/README.md",
            key: "g2_is_zero",
            value: script_len(G2Affine::is_zero_keep_element()),
        },
    ]
}

#[test]
fn readme_metrics_are_current() {
    let update = env::var_os("UPDATE_PRIMITIVE_METRICS").is_some();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));

    for metric in metrics() {
        let path = root.join(metric.readme);
        let contents = fs::read_to_string(&path).unwrap();
        let start = format!("<!-- metric:{} -->", metric.key);
        let end = format!("<!-- /metric:{} -->", metric.key);
        let start_index = contents.find(&start).unwrap_or_else(|| {
            panic!(
                "missing metric marker `{}` in {}",
                metric.key, metric.readme
            )
        });
        let value_start = start_index + start.len();
        let relative_end = contents[value_start..]
            .find(&end)
            .unwrap_or_else(|| panic!("missing closing metric marker `{}`", metric.key));
        let value_end = value_start + relative_end;
        let current = &contents[value_start..value_end];

        if update {
            let mut updated = contents;
            updated.replace_range(value_start..value_end, &metric.value.to_string());
            fs::write(path, updated).unwrap();
        } else {
            assert_eq!(
                current,
                metric.value.to_string(),
                "{} is stale; run UPDATE_PRIMITIVE_METRICS=1 cargo test --test primitive_metrics",
                metric.readme,
            );
        }
    }
}
