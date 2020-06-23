#![feature(test)]

use ahash;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use fxhash;
use std::{
    any::type_name,
    cmp::min,
    collections::hash_map::RandomState,
    default::Default,
    hash::{BuildHasher, Hasher},
};
use twox_hash;
use xxhrs::{
    EntropyPool, RandomStateXXH32, RandomStateXXH3_128, RandomStateXXH3_64, RandomStateXXH64,
    XXH32, XXH3_128, XXH3_64, XXH64,
};

pub const DATA: &[u8] = include_bytes!("../src/fixtures/data");
const ENTROPY: EntropyPool = EntropyPool {
    entropy: *include_bytes!("../src/fixtures/secret_entropy"),
};

pub fn type_basename<T>() -> &'static str {
    type_name::<T>().rsplit("::").next().unwrap()
}

fn bench_all(c: &mut Criterion) {
    let mut g = c.benchmark_group("hashes");

    let mut sz: usize = 0;
    loop {
        macro_rules! b {
            ($name:expr, $fn:expr) => {{
                let id = BenchmarkId::new($name, sz);
                g.throughput(Throughput::Bytes(sz as u64));
                g.bench_with_input(id, &DATA[0..sz], |b, d| {
                    b.iter(|| $fn(d));
                });
            }};
        };

        macro_rules! b_streaming {
            ($name:expr, $fn:expr) => {{
                b!($name, |d| {
                    let mut h = $fn();
                    h.write(d);
                    h.finish()
                });
            }};
        };

        macro_rules! b_buildhash {
            ($name:expr, $t:ty) => {{
                let builder = <$t>::default();
                b_streaming!($name, || black_box(&builder).build_hasher())
            }};
        };

        macro_rules! b_xxhash {
            ($t:ty) => {{
                let n = type_basename::<$t>();
                b!(format!("{}::hash", n), |d| <$t>::hash(d));
                b_streaming!(format!("{}::new", n), || <$t>::new());
            }};
        };

        macro_rules! b_xxh3 {
            ($t:ty) => {{
                let n = type_basename::<$t>();
                b!(format!("{}::hash", n), |d| <$t>::hash(d));
                b!(format!("{}::hash_with_seed", n), |d| <$t>::hash_with_seed(
                    black_box(9055972853411395268),
                    d
                ));
                b!(format!("{}::hash_with_entropy", n), |d| {
                    <$t>::hash_with_entropy(black_box(&ENTROPY), d)
                });
                b!(format!("{}::hash_with_entropy_buffer", n), |d| unsafe {
                    <$t>::hash_with_entropy_buffer(black_box(&ENTROPY.entropy), d)
                });

                b_streaming!(format!("{}::new", n), || <$t>::new());
                b_streaming!(format!("{}::with_entropy", n), || <$t>::with_entropy(
                    black_box(&ENTROPY)
                ));
                b_streaming!(format!("{}::with_entropy_buffer", n), || unsafe {
                    <$t>::with_entropy_buffer(black_box(&ENTROPY.entropy))
                });
            }};
        };

        b_xxhash!(XXH32);
        b_xxhash!(XXH64);

        b_xxh3!(XXH3_64);
        b_xxh3!(XXH3_128);

        b_buildhash!("xxhrs::RandomStateXXH32", RandomStateXXH32);
        b_buildhash!("xxhrs::RandomStateXXH64", RandomStateXXH64);

        b_buildhash!("xxhrs::RandomStateXXH3_64", RandomStateXXH3_64);
        b_buildhash!("xxhrs::RandomStateXXH3_128", RandomStateXXH3_128);

        b_buildhash!("RandomState", RandomState);
        b_buildhash!(
            "twox_hash::RandomXxHashBuilder32",
            twox_hash::RandomXxHashBuilder32
        );
        b_buildhash!(
            "twox_hash::RandomXxHashBuilder64",
            twox_hash::RandomXxHashBuilder64
        );
        b_buildhash!("fxhash::FxBuildHasher", fxhash::FxBuildHasher);
        b_buildhash!("ahash::RandomState", ahash::RandomState);

        // Benchmark again with more data
        if sz == 0 {
            sz = 1;
        } else if sz < DATA.len() {
            sz = min(sz * 2, DATA.len());
        } else {
            break;
        }
    }
}

criterion_group!(benches, bench_all);
criterion_main!(benches);
