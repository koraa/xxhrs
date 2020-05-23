use std::{
    default::Default, marker::PhantomData, hash::Hasher,
    mem::MaybeUninit, os::raw::c_void
};

use crate::{
    entropy::EntropyPool, xxhash_bindings as C
};

// XXH3_64bits, XXH3_64bits_withSecret, XXH3_64bits_withSeed,
// XXH3_64bits_reset, XXH3_64bits_reset_withSeed, XXH3_64bits_reset_withSecret,
// XXH3_64bits_update, XXH3_64bits_digest
//
// XXH3_128bits, XXH3_128bits_withSecret, XXH3_128bits_withSeed
// XXH3_128bits_reset, XXH3_128bits_reset_withSeed, XXH3_128bits_reset_withSecret,
// XXH3_128bits_update, XXH3_128bits_digest

pub struct XXH3_64<'a> {
    state: C::XXH3_state_t,
    entropy_lifetime: PhantomData<&'a [u8]>
}

impl Default for XXH3_64<'_> {
    fn default() -> Self { Self::new() }
}

impl XXH3_64<'_> {
    pub fn hash(bytes: &[u8]) -> u64 {
        unsafe {
            C::XXH3_64bits(bytes.as_ptr() as *const c_void, bytes.len())
        }
    }

    pub unsafe fn hash_with_entropy_buffer(entropy: &[u8], bytes: &[u8]) -> u64 {
        assert!(entropy.len() >= (C::XXH3_SECRET_SIZE_MIN) as usize);
        C::XXH3_64bits_withSecret(
            bytes.as_ptr() as *const c_void, bytes.len(),
            entropy.as_ptr() as *const c_void, entropy.len())
    }

    pub fn hash_with_entropy(entropy: &EntropyPool, bytes: &[u8]) -> u64 {
        unsafe {
            Self::hash_with_entropy_buffer(&entropy.entropy, bytes)
        }
    }

    pub fn hash_with_seed(seed: u64, bytes: &[u8]) -> u64 {
        unsafe {
            C::XXH3_64bits_withSeed(bytes.as_ptr() as *const c_void, bytes.len(), seed)
        }
    }

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

    pub unsafe fn with_entropy_buffer<'a>(entropy: &'a [u8]) -> XXH3_64<'a> {
        assert!(entropy.len() >= (C::XXH3_SECRET_SIZE_MIN) as usize);
        let mut r = MaybeUninit::<C::XXH3_state_t>::uninit();
        C::XXH3_64bits_reset_withSecret(
            r.as_mut_ptr() as *mut C::XXH3_state_t,
            entropy.as_ptr() as *const c_void, entropy.len());
        XXH3_64 {
            state: r.assume_init(),
            entropy_lifetime: PhantomData,
        }
    }

    pub fn with_entropy(entropy: &EntropyPool) -> XXH3_64<'static> {
        unsafe {
            let mut r = MaybeUninit::<C::XXH3_state_t>::uninit();
            C::XXH3_XXHRS_64bits_reset_withSecretCopy(
                r.as_mut_ptr() as *mut C::XXH3_state_t,
                entropy.entropy.as_ptr() as *const c_void);
            XXH3_64 {
                state: r.assume_init(),
                entropy_lifetime: PhantomData,
            }
        }
    }
}

impl Hasher for XXH3_64<'_> {
    fn write(&mut self, bytes: &[u8]) {
        unsafe {
            C::XXH3_64bits_update(&mut self.state, bytes.as_ptr() as *const c_void, bytes.len());
        }
    }

    fn finish(&self) -> u64 {
        unsafe { C::XXH3_64bits_digest(&self.state) }
    }
}

pub struct XXH3_128<'a> {
    state: C::XXH3_state_t,
    entropy_lifetime: PhantomData<&'a [u8]>
}

impl Default for XXH3_128<'_> {
    fn default() -> Self { Self::new() }
}

fn xxh128_to_u128(val: C::XXH128_hash_t) -> u128 {
    (val.low64 as u128) | (val.high64 as u128) << 64
}

impl XXH3_128<'_> {
    pub fn hash(bytes: &[u8]) -> u128 {
        let r = unsafe {
            C::XXH3_128bits(bytes.as_ptr() as *const c_void, bytes.len())
        };
        xxh128_to_u128(r)
    }

    pub unsafe fn hash_with_entropy_buffer(entropy: &[u8], bytes: &[u8]) -> u128 {
        assert!(entropy.len() >= (C::XXH3_SECRET_SIZE_MIN) as usize);
        let r = C::XXH3_128bits_withSecret(
            bytes.as_ptr() as *const c_void, bytes.len(),
            entropy.as_ptr() as *const c_void, entropy.len());
        xxh128_to_u128(r)
    }

    pub fn hash_with_entropy(entropy: &EntropyPool, bytes: &[u8]) -> u128 {
        unsafe {
            Self::hash_with_entropy_buffer(&entropy.entropy, bytes)
        }
    }

    pub fn hash_with_seed(seed: u64, bytes: &[u8]) -> u128 {
        let r = unsafe {
            C::XXH3_128bits_withSeed(bytes.as_ptr() as *const c_void, bytes.len(), seed)
        };
        xxh128_to_u128(r)
    }

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

    pub unsafe fn with_entropy_buffer<'a>(entropy: &'a [u8]) -> XXH3_128<'a> {
        assert!(entropy.len() >= (C::XXH3_SECRET_SIZE_MIN) as usize);
        let mut r = MaybeUninit::<C::XXH3_state_t>::uninit();
        C::XXH3_128bits_reset_withSecret(
            r.as_mut_ptr() as *mut C::XXH3_state_t,
            entropy.as_ptr() as *const c_void, entropy.len());
        XXH3_128 {
            state: r.assume_init(),
            entropy_lifetime: PhantomData,
        }
    }

    pub fn with_entropy(entropy: &EntropyPool) -> XXH3_128<'static> {
        unsafe {
            let mut r = MaybeUninit::<C::XXH3_state_t>::uninit();
            C::XXH3_XXHRS_128bits_reset_withSecretCopy(
                r.as_mut_ptr() as *mut C::XXH3_state_t,
                entropy.entropy.as_ptr() as *const c_void);
            XXH3_128 {
                state: r.assume_init(),
                entropy_lifetime: PhantomData,
            }
        }
    }

    pub fn write(&mut self, bytes: &[u8]) {
        unsafe {
            C::XXH3_128bits_update(&mut self.state, bytes.as_ptr() as *const c_void, bytes.len());
        }
    }

    pub fn finish(&self) -> u128 {
        let r = unsafe { C::XXH3_128bits_digest(&self.state) };
        xxh128_to_u128(r)
    }
}
