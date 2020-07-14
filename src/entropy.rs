use crate::xxhash_bindings as C;
use std::{fmt, os::raw::c_void};

#[cfg(feature = "random_entropy")]
use getrandom::getrandom;

pub const ENTROPY_POOL_SIZE: usize = C::XXH3_SECRET_DEFAULT_SIZE as usize;

#[derive(Clone)]
pub struct EntropyPool {
    pub entropy: [u8; ENTROPY_POOL_SIZE as usize],
}

impl PartialEq for EntropyPool {
    #[inline]
    fn eq(&self, otr: &Self) -> bool {
        let a: &[u8] = &self.entropy;
        let b: &[u8] = &otr.entropy;
        a == b
    }
}

impl fmt::Debug for EntropyPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EntropyPool { entropy: [")?;
        for (idx, v) in self.entropy.iter().enumerate() {
            if idx != 0 {
                f.write_str(", ")?
            };
            f.write_fmt(format_args!("{}", v))?;
        }
        f.write_str("] }")
    }
}

impl Eq for EntropyPool {}

impl EntropyPool {
    #[inline]
    fn new() -> Self {
        Self {
            entropy: [0u8; ENTROPY_POOL_SIZE],
        }
    }

    #[inline]
    #[cfg(feature = "random_entropy")]
    pub fn randomize() -> Self {
        let mut r = Self::new();
        getrandom(&mut r.entropy).unwrap();

        r
    }

    #[inline]
    pub fn with_seed(seed: u64) -> Self {
        let mut r = Self::new();
        unsafe { C::XXH3_XXHRS_initCustomSecret(r.entropy.as_mut_ptr(), seed) }

        r
    }

    #[inline]
    pub fn with_key(key: &[u8]) -> Self {
        let mut r = Self::new();
        unsafe {
            C::XXH3_generateSecret(
                r.entropy.as_mut_ptr() as *mut c_void,
                key.as_ptr() as *const c_void,
                key.len() as u64,
            );
        }
        r
    }
}
