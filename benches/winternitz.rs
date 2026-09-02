//! Host-side Winternitz key-generation and signing diagnostic.
//!
//! Run with `cargo bench --bench winternitz`. Timings are diagnostics rather
//! than consensus metrics; record the CPU, toolchain, profile, sample count,
//! and dispersion whenever quoting them.

use bitcoin_lab::signatures::winternitz::{FastWots32, Wots, Wots32};
use std::{hint::black_box, time::Instant};

const MESSAGE: [u8; 32] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
];
const SAMPLES: usize = 31;
const ITERATIONS: usize = 200;

fn measure(mut operation: impl FnMut()) -> Vec<f64> {
    for _ in 0..20 {
        operation();
    }

    let mut nanos_per_operation = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let start = Instant::now();
        for _ in 0..ITERATIONS {
            operation();
        }
        nanos_per_operation.push(start.elapsed().as_nanos() as f64 / ITERATIONS as f64);
    }
    nanos_per_operation.sort_by(f64::total_cmp);
    nanos_per_operation
}

fn report(label: &str, samples: &[f64]) {
    let median = samples[samples.len() / 2];
    let p10 = samples[samples.len() / 10];
    let p90 = samples[samples.len() * 9 / 10];
    println!("{label:24} median={median:10.0} ns  p10={p10:10.0}  p90={p90:10.0}");
}

fn main() {
    let legacy_secret = vec![0x42; 20];
    println!(
        "profile=release target={}-{} samples={} iterations/sample={}",
        std::env::consts::ARCH,
        std::env::consts::OS,
        SAMPLES,
        ITERATIONS
    );

    report(
        "legacy public key",
        &measure(|| {
            black_box(Wots32::generate_public_key(black_box(&legacy_secret)));
        }),
    );
    report(
        "fast public key",
        &measure(|| {
            let key = FastWots32::signing_key_from_seed(black_box([0x42; 32]));
            black_box(FastWots32::public_key(black_box(&key)));
        }),
    );
    report(
        "legacy sign",
        &measure(|| {
            black_box(Wots32::sign(black_box(&legacy_secret), black_box(&MESSAGE)));
        }),
    );
    report(
        "fast sign",
        &measure(|| {
            let key = FastWots32::signing_key_from_seed(black_box([0x42; 32]));
            black_box(FastWots32::sign(key, black_box(&MESSAGE)));
        }),
    );
}
