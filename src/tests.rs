use crate::{
    entropy::{EntropyPool, ENTROPY_POOL_SIZE},
    xxh3::{XXH3_128, XXH3_64},
    xxhash::{XXH32, XXH64},
};
use std::collections::{HashMap, HashSet};
use std::hash::{BuildHasher, Hasher};
use std::{cmp::min, default::Default};

#[cfg(feature = "random_entropy")]
use crate::buildhash::{
    RandomStateXXH32, RandomStateXXH3_128, RandomStateXXH3_64, RandomStateXXH64,
};

const SEED32: u32 = 0xf7649871;
const SEED64: u64 = 0x06cd630df7649871;
const XXH32_HASH: u32 = 0xf466cd9b;
const XXH32_SEEDED: u32 = 0x7ac7100f;
const XXH64_HASH: u64 = 0xb047e931fe218abd;
const XXH64_SEEDED: u64 = 0x12b0dbd4bd5ac33a;
const XXH3_64_HASH: u64 = 0x8a24edfe37edf1ea;
const XXH3_64_SEEDED: u64 = 0xbf15a1f1e41d08ae;
const XXH3_64_KEYED: u64 = 0x8ed31a1c680cec2a;
const XXH3_128_HASH: u128 = 0x085fd9804f34051d8a24edfe37edf1ea;
const XXH3_128_SEEDED: u128 = 0x9c43c2c76f8b3de0bf15a1f1e41d08ae;
const XXH3_128_KEYED: u128 = 0xdf2cabdf86a50f6e8ed31a1c680cec2a;

const SECRET: &[u8] = include_bytes!("fixtures/secret");
const DATA: &[u8] = include_bytes!("fixtures/data");

static SEED64_ENTROPY: EntropyPool = EntropyPool {
    entropy: *include_bytes!("fixtures/seed64_entropy"),
};
const SECRET_ENTROPY: EntropyPool = EntropyPool {
    entropy: *include_bytes!("fixtures/secret_entropy"),
};

const ENTROPY_POOL_42_DEBUG: &str = include_str!("fixtures/entropy_pool_42_debug");

#[test]
fn test_entropy_derivation() {
    assert_eq!(EntropyPool::with_key(&SECRET), SECRET_ENTROPY);
}

#[test]
fn test_one_shot() {
    assert_eq!(XXH32::hash(DATA), XXH32_HASH);
    assert_eq!(XXH32::hash_with_seed(SEED32, DATA), XXH32_SEEDED);
    assert_eq!(XXH64::hash(DATA), XXH64_HASH);
    assert_eq!(XXH64::hash_with_seed(SEED64, DATA), XXH64_SEEDED);
    assert_eq!(XXH3_64::hash(DATA), XXH3_64_HASH);
    assert_eq!(
        XXH3_64::hash_with_entropy(&SEED64_ENTROPY, DATA),
        XXH3_64_SEEDED
    );
    assert_eq!(
        XXH3_64::hash_with_entropy(&SECRET_ENTROPY, DATA),
        XXH3_64_KEYED
    );
    assert_eq!(XXH3_128::hash(DATA), XXH3_128_HASH);
    assert_eq!(
        XXH3_128::hash_with_entropy(&SEED64_ENTROPY, DATA),
        XXH3_128_SEEDED
    );
    assert_eq!(
        XXH3_128::hash_with_entropy(&SECRET_ENTROPY, DATA),
        XXH3_128_KEYED
    );

    unsafe {
        assert_eq!(
            XXH3_64::hash_with_entropy_buffer(&SEED64_ENTROPY.entropy, DATA),
            XXH3_64_SEEDED
        );
        assert_eq!(
            XXH3_64::hash_with_entropy_buffer(&SECRET_ENTROPY.entropy, DATA),
            XXH3_64_KEYED
        );
        assert_eq!(
            XXH3_128::hash_with_entropy_buffer(&SEED64_ENTROPY.entropy, DATA),
            XXH3_128_SEEDED
        );
        assert_eq!(
            XXH3_128::hash_with_entropy_buffer(&SECRET_ENTROPY.entropy, DATA),
            XXH3_128_KEYED
        );
    }
}

#[test]
fn test_streaming() {
    const BLOCK_SIZE: &[usize] = &[0, 1, 2, 3, 4, 7, 11, 31, 63, 89];

    macro_rules! test_stream {
        // Full version
        ($out:ident <- $typ:ty: $var:expr) => {{
            let mut gen : $typ = $var;

            gen.finish(); // can finish before write

            let mut gen_clone_1 = gen.clone(); // test clone

            let mut off : usize = 0;
            for sz in BLOCK_SIZE.iter().cycle() {
                let end = min(off+sz, DATA.len());
                let block = &DATA[off..end];
                off = end;

                gen.write(block);
                gen_clone_1.write(block);

                if off == DATA.len() {
                    break;
                }
            }

            let gen_clone_2 = gen.clone(); // test clone

            assert_eq!(gen.finish(), $out);
            assert_eq!(gen.finish(), $out); // can finish twice
            assert_eq!(gen_clone_1.finish(), $out);
            assert_eq!(gen_clone_2.finish(), $out);
        }};

        // Without type
        ($out:ident <- $var:expr) => {
            test_stream!($out <- _: $var);
        };

        // Termination
        () => {};

        // List expansion (full)
        ($out:ident <- $typ:ty: $var:expr, $($rest:tt)*) => {{
            test_stream!($out <- $typ: $var);
            test_stream!($($rest)*);
        }};

        // List expansion (no type)
        ($out:ident <- $var:expr, $($rest:tt)*) => {{
            test_stream!($out <- $var);
            test_stream!($($rest)*);
        }};
    };

    test_stream!(
        XXH32_HASH   <- XXH32::new(),
        XXH32_SEEDED <- XXH32::with_seed(SEED32),

        XXH64_HASH   <- XXH64::new(),
        XXH64_SEEDED <- XXH64::with_seed(SEED64),

        XXH3_64_HASH   <- XXH3_64::new(),
        XXH3_64_SEEDED <- XXH3_64::with_entropy(&SEED64_ENTROPY),
        XXH3_64_KEYED  <- XXH3_64::with_entropy(&SECRET_ENTROPY),

        XXH3_128_HASH   <- XXH3_128::new(),
        XXH3_128_SEEDED <- XXH3_128::with_entropy(&SEED64_ENTROPY),
        XXH3_128_KEYED  <- XXH3_128::with_entropy(&SECRET_ENTROPY),

        // Entropy cloning
        XXH3_64_SEEDED <- { XXH3_64::with_entropy( &SEED64_ENTROPY.clone() )},
        XXH3_64_KEYED  <- { XXH3_64::with_entropy( &SECRET_ENTROPY.clone() )},
        XXH3_128_SEEDED <- { XXH3_128::with_entropy( &SEED64_ENTROPY.clone() )},
        XXH3_128_KEYED  <- { XXH3_128::with_entropy( &SECRET_ENTROPY.clone() )},

        XXH32_HASH <- XXH32: Default::default(),
        XXH64_HASH <- XXH64: Default::default(),
        XXH3_64_HASH  <- XXH3_64: Default::default(),
        XXH3_128_HASH <- XXH3_128: Default::default(),
    );

    unsafe {
        test_stream!(
            XXH3_64_SEEDED <- { XXH3_64::with_entropy_buffer(&SEED64_ENTROPY.entropy) },
            XXH3_64_KEYED  <- { XXH3_64::with_entropy_buffer(&SECRET_ENTROPY.entropy) },
            XXH3_128_SEEDED <- { XXH3_128::with_entropy_buffer(&SEED64_ENTROPY.entropy) },
            XXH3_128_KEYED  <- { XXH3_128::with_entropy_buffer(&SECRET_ENTROPY.entropy) },
        );
    }
}

#[test]
fn test_hasher_iface() {
    let mut h = XXH64::with_seed(SEED64);
    let mut h3 = XXH3_64::with_entropy(&SEED64_ENTROPY);
    Hasher::write(&mut h, DATA);
    Hasher::write(&mut h3, DATA);
    assert_eq!(Hasher::finish(&h), XXH64_SEEDED);
    assert_eq!(Hasher::finish(&h3), XXH3_64_SEEDED);
}

#[test]
#[cfg(feature = "random_entropy")]
fn test_random_entropy_pool() {
    assert_ne!(EntropyPool::randomize(), EntropyPool::randomize());
    assert_ne!(
        XXH3_128::hash_with_entropy(&EntropyPool::randomize(), b""),
        XXH3_128::hash_with_entropy(&EntropyPool::randomize(), b"")
    );
}

#[test]
#[cfg(feature = "random_entropy")]
fn test_entropy_pool_clone() {
    let pool = EntropyPool::randomize();
    assert_eq!(pool, pool.clone());
}

#[test]
#[cfg(feature = "random_entropy")]
fn test_build_hasher() {
    let mut set = HashSet::<u128>::new();

    macro_rules! hash_now {
        ($bh:expr, $val:expr) => {{
            let mut hasher = $bh.build_hasher();
            hasher.write($val);
            hasher.finish()
        }};
    }

    macro_rules! test_random_state_instance {
        ($hasher:expr) => {{
            let gen = $hasher;
            let a = hash_now!(gen, b"42");
            assert_eq!(a, hash_now!(gen, b"42"));
            assert_eq!(a, hash_now!(gen.clone(), b"42")); // Cloning RandomState
            assert!(set.insert(a as u128));
        }};
    }

    macro_rules! test_random_state {
        ($typ:ty) => {{
            for _ in 0..10 {
                test_random_state_instance!(<$typ>::new());
                test_random_state_instance!(<$typ>::default());
            }
        }};
    }

    test_random_state!(RandomStateXXH32);
    test_random_state!(RandomStateXXH64);
    test_random_state!(RandomStateXXH3_64);
    test_random_state!(RandomStateXXH3_128);
}

#[test]
#[cfg(feature = "random_entropy")]
fn test_hash_set() {
    macro_rules! test_random_state {
        ($typ:ty) => {{
            let mut hm = HashMap::<u128, u128, $typ>::default();
            let mut hs = HashSet::<u128, $typ>::default();
            for ix in 0..10240 {
                assert_eq!(hm.insert(ix, 42), None);
                assert!(hs.insert(ix));
            }
        }};
    };

    test_random_state!(RandomStateXXH64);
    test_random_state!(RandomStateXXH3_64);
}

#[test]
#[cfg(feature = "random_entropy")]
fn test_debug_print() {
    macro_rules! assert_debug {
        ($in:expr, $out:expr) => {
            assert_eq!(format!("{:?}", $in), $out);
        };
    };

    let pool = EntropyPool {
        entropy: [42u8; ENTROPY_POOL_SIZE],
    };

    assert_debug!(pool, ENTROPY_POOL_42_DEBUG);
    assert_debug!(
        RandomStateXXH32 { seed: 42 },
        "RandomStateXXH32 { seed: 42 }"
    );
    assert_debug!(
        RandomStateXXH64 { seed: 42 },
        "RandomStateXXH64 { seed: 42 }"
    );
    assert_debug!(
        RandomStateXXH3_64 { pool: pool.clone() },
        format!("RandomStateXXH3_64 {{ pool: {} }}", ENTROPY_POOL_42_DEBUG)
    );
    assert_debug!(
        RandomStateXXH3_128 { pool: pool.clone() },
        format!("RandomStateXXH3_128 {{ pool: {} }}", ENTROPY_POOL_42_DEBUG)
    );
}
