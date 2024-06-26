use std::default::Default;
use std::hash::Hasher;
use std::mem::MaybeUninit;
use std::os::raw::c_void;

use crate::C;

/// xxhash 32 bit c library bindings
///
/// Streaming mode is used just like the `Hasher` trait, but does
/// not implement the trait because this returns u32, hasher requires u64
#[derive(Clone)]
pub struct XXH32 {
    state: C::XXH32_state_t,
}

impl Default for XXH32 {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl XXH32 {
    /// One-shot hashing
    #[inline]
    pub fn hash(bytes: &[u8]) -> u32 {
        XXH32::hash_with_seed(0, bytes)
    }

    /// One-shot hashing with seed
    #[inline]
    pub fn hash_with_seed(seed: u32, bytes: &[u8]) -> u32 {
        unsafe { C::XXH32(bytes.as_ptr() as *const c_void, bytes.len(), seed) }
    }

    /// Streaming hashing
    #[inline]
    pub fn new() -> XXH32 {
        XXH32::with_seed(0)
    }

    /// Streaming hashing with seed
    #[inline]
    pub fn with_seed(seed: u32) -> XXH32 {
        unsafe {
            let mut r = MaybeUninit::<C::XXH32_state_t>::uninit();
            // SAFETY: Writes to padding fields may be optimized away on the C
            // side since they are never accessed. To avoid UB from
            // r.assume_uninit(), we initialize them to 0.
            let r_ptr = r.as_mut_ptr();
            (*r_ptr).reserved = 0;
            C::XXH32_reset(r_ptr as *mut C::XXH32_state_t, seed);
            XXH32 {
                state: r.assume_init(),
            }
        }
    }

    #[inline]
    pub fn write(&mut self, bytes: &[u8]) {
        unsafe {
            C::XXH32_update(
                &mut self.state,
                bytes.as_ptr() as *const c_void,
                bytes.len(),
            );
        }
    }

    #[inline]
    pub fn finish(&self) -> u32 {
        unsafe { C::XXH32_digest(&self.state) }
    }
}

/// xxhash 32 bit c library bindings
#[derive(Clone)]
pub struct XXH64 {
    state: C::XXH64_state_t,
}

impl Default for XXH64 {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl XXH64 {
    /// One-shot hashing
    #[inline]
    pub fn hash(bytes: &[u8]) -> u64 {
        XXH64::hash_with_seed(0, bytes)
    }

    /// One-shot hashing with seed
    #[inline]
    pub fn hash_with_seed(seed: u64, bytes: &[u8]) -> u64 {
        unsafe { C::XXH64(bytes.as_ptr() as *const c_void, bytes.len(), seed) }
    }

    /// Streaming hashing
    #[inline]
    pub fn new() -> XXH64 {
        XXH64::with_seed(0)
    }

    /// Streaming hashing with seed
    #[inline]
    pub fn with_seed(seed: u64) -> XXH64 {
        unsafe {
            let mut r = MaybeUninit::<C::XXH64_state_t>::uninit();
            // SAFETY: Writes to padding fields may be optimized away on the C
            // side since they are never accessed. To avoid UB from
            // r.assume_uninit(), we initialize them to 0.
            let r_ptr = r.as_mut_ptr();
            (*r_ptr).reserved32 = 0;
            (*r_ptr).reserved64 = 0;
            C::XXH64_reset(r_ptr as *mut C::XXH64_state_t, seed);
            XXH64 {
                state: r.assume_init(),
            }
        }
    }
}

impl Hasher for XXH64 {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        unsafe {
            C::XXH64_update(
                &mut self.state,
                bytes.as_ptr() as *const c_void,
                bytes.len(),
            );
        }
    }

    #[inline]
    fn finish(&self) -> u64 {
        unsafe { C::XXH64_digest(&self.state) }
    }
}
