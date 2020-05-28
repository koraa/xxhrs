use std::{hash::BuildHasher, default::Default};
use getrandom::getrandom;
use crate::{
    xxhash::{XXH32, XXH64},
    xxh3::{XXH3_64, XXH3_128},
    entropy::EntropyPool,
};

pub struct RandomStateXXH32 {
    seed: u32
}

impl Default for RandomStateXXH32 {
    fn default() -> Self { Self::new() }
}

impl RandomStateXXH32 {
    pub fn new() -> Self {
        let mut seed = [0u8; 4];
        getrandom(&mut seed).unwrap();
        Self { seed: u32::from_ne_bytes(seed) }
    }

    pub fn build_hasher(&self) -> XXH32 {
        XXH32::with_seed(self.seed)
    }
}

pub struct RandomStateXXH64 {
    seed: u64
}

impl Default for RandomStateXXH64 {
    fn default() -> Self { Self::new() }
}

impl RandomStateXXH64 {
    pub fn new() -> Self {
        let mut seed = [0u8; 8];
        getrandom(&mut seed).unwrap();
        Self { seed: u64::from_ne_bytes(seed) }
    }
}

impl BuildHasher for RandomStateXXH64 {
    type Hasher = XXH64;

    fn build_hasher(&self) -> Self::Hasher {
        Self::Hasher::with_seed(self.seed)
    }
}

#[derive(Clone)]
pub struct RandomStateXXH3_64 {
    pool: EntropyPool
}

impl Default for RandomStateXXH3_64 {
    fn default() -> Self { Self::new() }
}

impl RandomStateXXH3_64 {
    pub fn new() -> Self {
        Self { pool: EntropyPool::randomize() }
    }
}

impl BuildHasher for RandomStateXXH3_64 {
    type Hasher = XXH3_64<'static>;

    fn build_hasher(&self) -> Self::Hasher {
        Self::Hasher::with_entropy(&self.pool)
    }
}

pub struct RandomStateXXH3_128 {
    pool: EntropyPool
}

impl Default for RandomStateXXH3_128 {
    fn default() -> Self { Self::new() }
}

impl RandomStateXXH3_128 {
    pub fn new() -> Self {
        Self { pool: EntropyPool::randomize() }
    }

    pub fn build_hasher(&self) -> XXH3_128<'static> {
        XXH3_128::with_entropy(&self.pool)
    }
}
