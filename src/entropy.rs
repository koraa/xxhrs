use std::fmt;
use getrandom::getrandom;
use tiny_keccak::{Xof, Shake, Hasher};
use crate::xxhash_bindings as C;

pub const ENTROPY_POOL_SIZE : usize = C::XXH3_SECRET_DEFAULT_SIZE as usize;

#[derive(Copy, Clone)]
pub struct EntropyPool {
    pub entropy: [u8; ENTROPY_POOL_SIZE as usize]
}

impl PartialEq for EntropyPool {
    fn eq(&self, otr: &Self) -> bool {
        let a : &[u8] = &self.entropy;
        let b : &[u8] = &otr.entropy;
        a == b
    }
}

impl fmt::Debug for EntropyPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EntropyPool { entropy: [")?;
        for (idx, v) in self.entropy.iter().enumerate() {
            if idx != 0 { f.write_str(", ")? };
            f.write_fmt(format_args!("{}", v))?;
        }
        f.write_str("] }")
    }
}

impl Eq for EntropyPool {}

impl EntropyPool {
    fn new() -> Self {
        Self { entropy: [0u8; ENTROPY_POOL_SIZE] }
    }

    pub fn randomize() -> Self {
        let mut r = Self::new();
        getrandom(&mut r.entropy).unwrap();

        r
    }

    pub fn with_seed(seed: u64) -> Self {
        let mut r = Self::new();
        unsafe {
            C::XXH3_XXHRS_initCustomSecret(r.entropy.as_mut_ptr(), seed)
        }

        r
    }

    pub fn with_key_shake128(key: &[u8]) -> Self {
        let mut r = Self::new();
        let mut h = Shake::v128();
        h.update(key);
        h.squeeze(&mut r.entropy);

        r
    }
}
