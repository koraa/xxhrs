use crate::{
    entropy::EntropyPool,
    xxh3::{XXH3_128, XXH3_64},
    xxhash::{XXH32, XXH64},
};
use getrandom::getrandom;
use std::{default::Default, hash::BuildHasher};

#[derive(Clone)]
pub struct RandomStateXXH32 {
    pub proto: XXH32,
}

impl Default for RandomStateXXH32 {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl RandomStateXXH32 {
    #[inline]
    pub fn new() -> Self {
        let mut seed = [0u8; 4];
        getrandom(&mut seed).unwrap();
        Self {
            proto: XXH32::with_seed(u32::from_ne_bytes(seed)),
        }
    }

    #[inline]
    pub fn build_hasher(&self) -> XXH32 {
        self.proto.clone()
    }
}

#[derive(Clone)]
pub struct RandomStateXXH64 {
    pub proto: XXH64,
}

impl Default for RandomStateXXH64 {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl RandomStateXXH64 {
    pub fn new() -> Self {
        let mut seed = [0u8; 8];
        getrandom(&mut seed).unwrap();
        Self {
            proto: XXH64::with_seed(u64::from_ne_bytes(seed)),
        }
    }
}

impl BuildHasher for RandomStateXXH64 {
    type Hasher = XXH64;

    #[inline]
    fn build_hasher(&self) -> Self::Hasher {
        self.proto.clone()
    }
}

#[derive(Clone)]
pub struct RandomStateXXH3_64 {
    pub proto: XXH3_64<'static>,
}

impl Default for RandomStateXXH3_64 {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl RandomStateXXH3_64 {
    #[inline]
    pub fn new() -> Self {
        Self {
            proto: XXH3_64::with_entropy(&EntropyPool::randomize())
        }
    }
}

impl BuildHasher for RandomStateXXH3_64 {
    type Hasher = XXH3_64<'static>;

    #[inline]
    fn build_hasher(&self) -> Self::Hasher {
        self.proto.clone()
    }
}

#[derive(Clone)]
pub struct RandomStateXXH3_128 {
    pub proto: XXH3_128<'static>,
}

impl Default for RandomStateXXH3_128 {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl RandomStateXXH3_128 {
    #[inline]
    pub fn new() -> Self {
        Self {
            proto: XXH3_128::with_entropy(&EntropyPool::randomize()),
        }
    }

    #[inline]
    pub fn build_hasher(&self) -> XXH3_128<'static> {
        self.proto.clone()
    }
}
