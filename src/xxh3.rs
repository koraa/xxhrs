use std::default::Default;
use std::hash::Hasher;
use std::mem::MaybeUninit;
use std::os::raw::c_void;

use crate::xxhash_bindings as C;
// XXH3_64bits, XXH3_64bits_withSecret, XXH3_64bits_withSeed,
// XXH3_64bits_reset, XXH3_64bits_reset_withSeed, XXH3_64bits_reset_withSecret,
// XXH3_64bits_update, XXH3_64bits_digest
//
// XXH3_128bits, XXH3_128bits_withSecret, XXH3_128bits_withSeed
// XXH3_128bits_reset, XXH3_128bits_reset_withSeed, XXH3_128bits_reset_withSecret,
// XXH3_128bits_update, XXH3_128bits_digest

pub struct XXH3_64 {
    state: C::XXH3_state_t
}

impl Default for XXH3_64 {
    fn default() -> Self { Self::new() }
}

impl XXH3_64 {
    pub fn hash(bytes: &[u8]) -> u64 {
        unsafe {
            C::XXH3_64bits(bytes.as_ptr() as *const c_void, bytes.len())
        }
    }

    pub fn hash_with_secret(secret: &[u8], bytes: &[u8]) -> u64 {
        assert!(secret.len() >= (C::XXH3_SECRET_SIZE_MIN) as usize);
        unsafe {
            C::XXH3_64bits_withSecret(
                bytes.as_ptr() as *const c_void, bytes.len(),
                secret.as_ptr() as *const c_void, secret.len())
        }
    }

    pub fn hash_with_seed(seed: u64, bytes: &[u8]) -> u64 {
        unsafe {
            C::XXH3_64bits_withSeed(bytes.as_ptr() as *const c_void, bytes.len(), seed)
        }
    }

    pub fn new() -> XXH3_64 {
        unsafe {
            let mut r = MaybeUninit::<&C::XXH3_state_t>::uninit();
            C::XXH3_64bits_reset(r.as_mut_ptr() as *mut C::XXH3_state_t);
            XXH3_64 { state: *r.assume_init() }
        }
    }

    pub fn with_secret(secret: &[u8]) -> XXH3_64 {
        assert!(secret.len() >= (C::XXH3_SECRET_SIZE_MIN) as usize);
        unsafe {
            let mut r = MaybeUninit::<&C::XXH3_state_t>::uninit();
            C::XXH3_64bits_reset_withSecret(
                r.as_mut_ptr() as *mut C::XXH3_state_t,
                secret.as_ptr() as *const c_void, secret.len());
            XXH3_64 { state: *r.assume_init() }
        }
    }

    pub fn with_seed(seed: u64) -> XXH3_64 {
        unsafe {
            let mut r = MaybeUninit::<&C::XXH3_state_t>::uninit();
            C::XXH3_64bits_reset_withSeed(
                r.as_mut_ptr() as *mut C::XXH3_state_t, seed);
            XXH3_64 { state: *r.assume_init() }
        }
    }
}

impl Hasher for XXH3_64 {
    fn write(&mut self, bytes: &[u8]) {
        unsafe {
            C::XXH3_64bits_update(&mut self.state, bytes.as_ptr() as *const c_void, bytes.len());
        }
    }

    fn finish(&self) -> u64 {
        unsafe {
            C::XXH3_64bits_digest(&self.state)
        }
    }
}

pub struct XXH3_128 {
    state: C::XXH3_state_t
}

impl Default for XXH3_128 {
    fn default() -> Self { Self::new() }
}

fn xxh128_to_u128(val: C::XXH128_hash_t) -> u128 {
    (val.low64 as u128) | (val.high64 as u128) << 64
}

impl XXH3_128 {
    pub fn hash(bytes: &[u8]) -> u128 {
        let r = unsafe {
            C::XXH3_128bits(bytes.as_ptr() as *const c_void, bytes.len())
        };
        xxh128_to_u128(r)
    }

    pub fn hash_with_secret(secret: &[u8], bytes: &[u8]) -> u128 {
        assert!(secret.len() >= (C::XXH3_SECRET_SIZE_MIN) as usize);
        let r = unsafe {
            C::XXH3_128bits_withSecret(
                bytes.as_ptr() as *const c_void, bytes.len(),
                secret.as_ptr() as *const c_void, secret.len())
        };
        xxh128_to_u128(r)
    }

    pub fn hash_with_seed(seed: u64, bytes: &[u8]) -> u128 {
        let r = unsafe {
            C::XXH3_128bits_withSeed(bytes.as_ptr() as *const c_void, bytes.len(), seed)
        };
        xxh128_to_u128(r)
    }

    pub fn new() -> XXH3_128 {
        unsafe {
            let mut r = MaybeUninit::<&C::XXH3_state_t>::uninit();
            C::XXH3_128bits_reset(r.as_mut_ptr() as *mut C::XXH3_state_t);
            XXH3_128 { state: *r.assume_init() }
        }
    }

    pub fn with_secret(secret: &[u8]) -> XXH3_128 {
        assert!(secret.len() >= (C::XXH3_SECRET_SIZE_MIN) as usize);
        unsafe {
            let mut r = MaybeUninit::<&C::XXH3_state_t>::uninit();
            C::XXH3_128bits_reset_withSecret(
                r.as_mut_ptr() as *mut C::XXH3_state_t,
                secret.as_ptr() as *const c_void, secret.len());
            XXH3_128 { state: *r.assume_init() }
        }
    }

    pub fn with_seed(seed: u64) -> XXH3_128 {
        unsafe {
            let mut r = MaybeUninit::<&C::XXH3_state_t>::uninit();
            C::XXH3_128bits_reset_withSeed(
                r.as_mut_ptr() as *mut C::XXH3_state_t, seed);
            XXH3_128 { state: *r.assume_init() }
        }
    }

    pub fn write(&mut self, bytes: &[u8]) {
        unsafe {
            C::XXH3_128bits_update(&mut self.state, bytes.as_ptr() as *const c_void, bytes.len());
        }
    }

    pub fn finish(&self) -> u128 {
        let r = unsafe {
            C::XXH3_128bits_digest(&self.state)
        };
        xxh128_to_u128(r)
    }
}
