use crate::{entropy::EntropyPool, xxhash_bindings as C};
use std::{default::Default, hash::Hasher, marker::PhantomData, mem::MaybeUninit, os::raw::c_void};

// XXH3_64bits, XXH3_64bits_withSecret, XXH3_64bits_withSeed,
// XXH3_64bits_reset, XXH3_64bits_reset_withSeed, XXH3_64bits_reset_withSecret,
// XXH3_64bits_update, XXH3_64bits_digest
//
// XXH3_128bits, XXH3_128bits_withSecret, XXH3_128bits_withSeed
// XXH3_128bits_reset, XXH3_128bits_reset_withSeed, XXH3_128bits_reset_withSecret,
// XXH3_128bits_update, XXH3_128bits_digest

/// xxh3 64 bit c library bindings
///
/// ::default() and ::new() are equivalent; they construct the unseeded
/// streaming variant…
#[derive(Clone)]
pub struct XXH3_64<'a> {
    state: C::XXH3_state_t,
    entropy_lifetime: PhantomData<&'a [u8]>,
}

impl Default for XXH3_64<'_> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl XXH3_64<'_> {
    /// One-shot hashing
    #[inline]
    pub fn hash(bytes: &[u8]) -> u64 {
        unsafe { C::XXH3_64bits(bytes.as_ptr() as *const c_void, bytes.len() as u64) }
    }

    /// One-shot hashing with custom entropy buffer.
    ///
    /// This corresponds to XXH3_64bits_withSecret. You probably want
    /// to use hash_with_entropy instead unless you really need to supply
    /// custom size entropy buffers, in which case this is the function
    /// to use.
    ///
    /// # Safety
    ///
    /// This function is marked unsafe just to encourage using the EntropyPool
    /// abstraction which makes it hard to produce particularly unsafe entropy
    /// pools.
    ///
    /// The entropy pool must be at least 136 bytes.
    #[inline]
    pub unsafe fn hash_with_entropy_buffer(entropy: &[u8], bytes: &[u8]) -> u64 {
        assert!(entropy.len() >= (C::XXH3_SECRET_SIZE_MIN) as usize);
        C::XXH3_64bits_withSecret(
            bytes.as_ptr() as *const c_void,
            bytes.len() as u64,
            entropy.as_ptr() as *const c_void,
            entropy.len() as u64,
        )
    }

    /// One-shot hashing with custom entropy buffer.
    ///
    /// This corresponds to XXH3_64bits_withSecret.
    #[inline]
    pub fn hash_with_entropy(entropy: &EntropyPool, bytes: &[u8]) -> u64 {
        unsafe { Self::hash_with_entropy_buffer(&entropy.entropy, bytes) }
    }

    /// One-shot hashing with seed
    #[inline]
    pub fn hash_with_seed(seed: u64, bytes: &[u8]) -> u64 {
        unsafe {
            C::XXH3_64bits_withSeed(bytes.as_ptr() as *const c_void, bytes.len() as u64, seed)
        }
    }

    /// Streaming hashing
    #[inline]
    pub fn new() -> XXH3_64<'static> {
        unsafe {
            let mut r = MaybeUninit::<C::XXH3_state_t>::uninit();
            C::XXH3_64bits_reset(r.as_mut_ptr() as *mut C::XXH3_state_t);
            XXH3_64 {
                state: r.assume_init(),
                entropy_lifetime: PhantomData,
            }
        }
    }

    /// Streaming hashing with custom entropy buffer.
    ///
    /// This corresponds to XXH3_64bits_reset_withSecret.
    ///
    /// This function is marked unsafe to discourage it's use; use with_entropy
    /// instead which copies the entropy (thus causing far fewer lifetime problems)
    /// and uses the safer EntropyPool abstraction.
    ///
    /// # Safety
    ///
    /// Use this function if you really want to avoid the entropy copy
    /// or if you really need to use a custom size entropy pool.
    ///
    /// The entropy pool must be at least 136 bytes.
    #[inline]
    pub unsafe fn with_entropy_buffer(entropy: &[u8]) -> XXH3_64 {
        assert!(entropy.len() >= (C::XXH3_SECRET_SIZE_MIN) as usize);
        let mut r = MaybeUninit::<C::XXH3_state_t>::uninit();
        C::XXH3_64bits_reset_withSecret(
            r.as_mut_ptr() as *mut C::XXH3_state_t,
            entropy.as_ptr() as *const c_void,
            entropy.len() as u64,
        );
        XXH3_64 {
            state: r.assume_init(),
            entropy_lifetime: PhantomData,
        }
    }

    /// Streaming hashing with custom entropy buffer.
    ///
    /// This corresponds to XXH3_64bits_reset_withSecret.
    #[inline]
    pub fn with_entropy(entropy: &EntropyPool) -> XXH3_64<'static> {
        unsafe {
            let mut r = MaybeUninit::<C::XXH3_state_t>::uninit();
            C::XXH3_XXHRS_64bits_reset_withSecretCopy(
                r.as_mut_ptr() as *mut C::XXH3_state_t,
                entropy.entropy.as_ptr() as *const c_void,
            );
            XXH3_64 {
                state: r.assume_init(),
                entropy_lifetime: PhantomData,
            }
        }
    }

    /// Streaming hashing with custom seed.
    #[inline]
    pub fn with_seed(seed: u64) -> XXH3_64<'static> {
        unsafe {
            let mut r = MaybeUninit::<C::XXH3_state_t>::uninit();
            C::XXH3_64bits_reset_withSeed(r.as_mut_ptr() as *mut C::XXH3_state_t, seed);
            XXH3_64 {
                state: r.assume_init(),
                entropy_lifetime: PhantomData,
            }
        }
    }
}

impl Hasher for XXH3_64<'_> {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        unsafe {
            C::XXH3_64bits_update(
                &mut self.state,
                bytes.as_ptr() as *const c_void,
                bytes.len() as u64,
            );
        }
    }

    #[inline]
    fn finish(&self) -> u64 {
        unsafe { C::XXH3_64bits_digest(&self.state) }
    }
}

/// xxh3 64 bit c library bindings
///
/// Streaming mode is used just like the `Hasher` trait, but does
/// not implement the trait because this returns u128, hasher requires u64
///
/// ::default() and ::new() are equivalent; they construct the unseeded
/// streaming variant…
#[derive(Clone)]
pub struct XXH3_128<'a> {
    state: C::XXH3_state_t,
    entropy_lifetime: PhantomData<&'a [u8]>,
}

impl Default for XXH3_128<'_> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

#[inline]
fn xxh128_to_u128(val: C::XXH128_hash_t) -> u128 {
    (val.low64 as u128) | (val.high64 as u128) << 64
}

impl XXH3_128<'_> {
    /// One-shot hashing
    #[inline]
    pub fn hash(bytes: &[u8]) -> u128 {
        let r = unsafe { C::XXH3_128bits(bytes.as_ptr() as *const c_void, bytes.len() as u64) };
        xxh128_to_u128(r)
    }

    /// One-shot hashing with custom entropy buffer.
    ///
    /// This corresponds to XXH3_64bits_withSecret. You probably want
    /// to use hash_with_entropy instead unless you really need to supply
    /// custom size entropy buffers, in which case this is the function
    /// to use.
    ///
    /// # Safety
    ///
    /// This function is marked unsafe just to encourage using the EntropyPool
    /// abstraction which makes it hard to produce particularly unsafe entropy
    /// pools.
    ///
    /// The entropy pool must be at least 136 bytes.
    #[inline]
    pub unsafe fn hash_with_entropy_buffer(entropy: &[u8], bytes: &[u8]) -> u128 {
        assert!(entropy.len() >= (C::XXH3_SECRET_SIZE_MIN) as usize);
        let r = C::XXH3_128bits_withSecret(
            bytes.as_ptr() as *const c_void,
            bytes.len() as u64,
            entropy.as_ptr() as *const c_void,
            entropy.len() as u64,
        );
        xxh128_to_u128(r)
    }

    /// One-shot hashing with custom entropy buffer.
    ///
    /// This corresponds to XXH3_64bits_withSecret.
    #[inline]
    pub fn hash_with_entropy(entropy: &EntropyPool, bytes: &[u8]) -> u128 {
        unsafe { Self::hash_with_entropy_buffer(&entropy.entropy, bytes) }
    }

    /// One-shot hashing with seed
    #[inline]
    pub fn hash_with_seed(seed: u64, bytes: &[u8]) -> u128 {
        let r = unsafe {
            C::XXH3_128bits_withSeed(bytes.as_ptr() as *const c_void, bytes.len() as u64, seed)
        };
        xxh128_to_u128(r)
    }

    /// Streaming hashing
    #[inline]
    pub fn new() -> XXH3_128<'static> {
        unsafe {
            let mut r = MaybeUninit::<C::XXH3_state_t>::uninit();
            C::XXH3_128bits_reset(r.as_mut_ptr() as *mut C::XXH3_state_t);
            XXH3_128 {
                state: r.assume_init(),
                entropy_lifetime: PhantomData,
            }
        }
    }

    /// Streaming hashing with custom entropy buffer.
    ///
    /// This corresponds to XXH3_64bits_reset_withSecret.
    ///
    /// This function is marked unsafe to discourage it's use; use with_entropy
    /// instead which copies the entropy (thus causing far fewer lifetime problems)
    /// and uses the safer EntropyPool abstraction.
    ///
    /// # Safety
    ///
    /// Use this function if you really want to avoid the entropy copy
    /// or if you really need to use a custom size entropy pool.
    ///
    /// The entropy pool must be at least 136 bytes.
    #[inline]
    pub unsafe fn with_entropy_buffer(entropy: &[u8]) -> XXH3_128 {
        assert!(entropy.len() >= (C::XXH3_SECRET_SIZE_MIN) as usize);
        let mut r = MaybeUninit::<C::XXH3_state_t>::uninit();
        C::XXH3_128bits_reset_withSecret(
            r.as_mut_ptr() as *mut C::XXH3_state_t,
            entropy.as_ptr() as *const c_void,
            entropy.len() as u64,
        );
        XXH3_128 {
            state: r.assume_init(),
            entropy_lifetime: PhantomData,
        }
    }

    /// Streaming hashing with custom entropy buffer.
    ///
    /// This corresponds to XXH3_64bits_reset_withSecret.
    #[inline]
    pub fn with_entropy(entropy: &EntropyPool) -> XXH3_128<'static> {
        unsafe {
            let mut r = MaybeUninit::<C::XXH3_state_t>::uninit();
            C::XXH3_XXHRS_128bits_reset_withSecretCopy(
                r.as_mut_ptr() as *mut C::XXH3_state_t,
                entropy.entropy.as_ptr() as *const c_void,
            );
            XXH3_128 {
                state: r.assume_init(),
                entropy_lifetime: PhantomData,
            }
        }
    }

    /// Streaming hashing with custom seed.
    #[inline]
    pub fn with_seed(seed: u64) -> XXH3_128<'static> {
        unsafe {
            let mut r = MaybeUninit::<C::XXH3_state_t>::uninit();
            C::XXH3_128bits_reset_withSeed(r.as_mut_ptr() as *mut C::XXH3_state_t, seed);
            XXH3_128 {
                state: r.assume_init(),
                entropy_lifetime: PhantomData,
            }
        }
    }

    #[inline]
    pub fn write(&mut self, bytes: &[u8]) {
        unsafe {
            C::XXH3_128bits_update(
                &mut self.state,
                bytes.as_ptr() as *const c_void,
                bytes.len() as u64,
            );
        }
    }

    #[inline]
    pub fn finish(&self) -> u128 {
        let r = unsafe { C::XXH3_128bits_digest(&self.state) };
        xxh128_to_u128(r)
    }
}
