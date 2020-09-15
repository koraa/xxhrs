use crate::C;
use std::{fmt, os::raw::c_void};

#[cfg(feature = "random_entropy")]
use getrandom::getrandom;

pub const ENTROPY_POOL_SIZE: usize = C::XXH3_SECRET_DEFAULT_SIZE as usize;

/// Besides seeded and unseeded variants, XXH3 provides a keyed (`withSecret`)
/// variant. This is a bit of a misnomer though, because these functions havea
/// not been formally verified as message authentication codes; they also do
/// not guarantee that the entire secret is used, the secret is impractically
/// large (tens to hundreds of bytes) and pathological secrets are not handled
/// well at all.
///
/// However, these functions are harder to revers than using seeds, in fact
/// the seeded variant internally just uses a modified secret.
///
/// This is why xxhrs provides support for these, but renames the secrets "EntropyPool"
/// to make it clear that it is not really a proper keyed hash.
///
/// You can generate a random EntropyPool or use the key derivation
/// function provided by the c library. You could also fill the secret manually,
/// for instance using HMAC-SHA256 or Kekkac, but this is probably overkill.
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

    /// Use the getrandom crate to create a randomized EntropyPool
    #[inline]
    #[cfg(feature = "random_entropy")]
    pub fn randomize() -> Self {
        let mut r = Self::new();
        getrandom(&mut r.entropy).unwrap();

        r
    }

    /// Use the higher quality entropy derivation scheme from variable
    /// length input keys
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
