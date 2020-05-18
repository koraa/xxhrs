use crate::xxhash::{XXH32, XXH64};
use crate::xxh3::{XXH3_64, XXH3_128};

const SEED32 :  u32 = 0xf7649871;
const SEED64 :  u64 = 0x06cd630df7649871;
const XXH32_HASH      :  u32 = 0xf466cd9b;
const XXH32_SEEDED    :  u32 = 0x7ac7100f;
const XXH64_HASH      :  u64 = 0xb047e931fe218abd;
const XXH64_SEEDED    :  u64 = 0x12b0dbd4bd5ac33a;
const XXH3_64_HASH    :  u64 = 0x59f41ae8c1844b05;
const XXH3_64_SEEDED  :  u64 = 0xa5b0cc590ec81f32;
const XXH3_64_KEYED   :  u64 = 0xe99760ca9f108aba;
const XXH3_128_HASH   : u128 = 0x085fd9804f34051d8a24edfe37edf1ea;
const XXH3_128_SEEDED : u128 = 0x9c43c2c76f8b3de0bf15a1f1e41d08ae;
const XXH3_128_KEYED  : u128 = 0x0f51af8851b4b5eaa51a2c60af4c8f82;

const SECRET : &[u8] = include_bytes!("fixtures/secret");
const DATA : &[u8] = include_bytes!("fixtures/data");

#[test]
fn test_one_shot() {
    assert_eq!(XXH32::hash(DATA),                   XXH32_HASH);
    assert_eq!(XXH32::hash_with_seed(SEED32, DATA), XXH32_SEEDED);
    assert_eq!(XXH64::hash(DATA),                   XXH64_HASH);
    assert_eq!(XXH64::hash_with_seed(SEED64, DATA), XXH64_SEEDED);
    assert_eq!(XXH3_64::hash(DATA),                     XXH3_64_HASH);
    assert_eq!(XXH3_64::hash_with_seed(SEED64, DATA),   XXH3_64_SEEDED);
    assert_eq!(XXH3_64::hash_with_secret(SECRET, DATA), XXH3_64_KEYED);
    assert_eq!(XXH3_128::hash(DATA),                     XXH3_128_HASH);
    assert_eq!(XXH3_128::hash_with_seed(SEED64, DATA),   XXH3_128_SEEDED);
    assert_eq!(XXH3_128::hash_with_secret(SECRET, DATA), XXH3_128_KEYED);
}
