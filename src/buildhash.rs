use std::{hash::BuildHasher, default::Default};
use getrandom::getrandom;
use crate::xxhash::{XXH32, XXH64};
use crate::xxh3::{XXH3_64, XXH3_128};

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

pub struct RandomStateXXH3_64 {
    secret: [u8; 32]
}

impl Default for RandomStateXXH3_64 {
    fn default() -> Self { Self::new() }
}

impl RandomStateXXH3_64 {
    pub fn new() -> Self {
        let mut secret = [0u8; 32];
        getrandom(&mut secret).unwrap();
        Self { secret }
    }
}

impl BuildHasher for RandomStateXXH3_64 {
    type Hasher = XXH3_64;

    fn build_hasher(&self) -> Self::Hasher {
        Self::Hasher::with_secret(&self.secret)
    }
}

pub struct RandomStateXXH3_128 {
    secret: [u8; 32]
}

impl Default for RandomStateXXH3_128 {
    fn default() -> Self { Self::new() }
}

impl RandomStateXXH3_128 {
    pub fn new() -> Self {
        let mut secret = [0u8; 32];
        getrandom(&mut secret).unwrap();
        Self { secret }
    }

    pub fn build_hasher(&self) -> XXH3_128 {
        XXH3_128::with_secret(&self.secret)
    }
}
