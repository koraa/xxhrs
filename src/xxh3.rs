use std::{default::Default, hash::Hasher, marker::PhantomData, mem::MaybeUninit, os::raw::c_void, rc::Rc};
use crate::{entropy::EntropyPool, xxhash_bindings as C};

// XXH3_64bits, XXH3_64bits_withSecret, XXH3_64bits_withSeed,
// XXH3_64bits_reset, XXH3_64bits_reset_withSeed, XXH3_64bits_reset_withSecret,
// XXH3_64bits_update, XXH3_64bits_digest
//
// XXH3_128bits, XXH3_128bits_withSecret, XXH3_128bits_withSeed
// XXH3_128bits_reset, XXH3_128bits_reset_withSeed, XXH3_128bits_reset_withSecret,
// XXH3_128bits_update, XXH3_128bits_digest

#[derive(Clone)]
pub enum EntropyRef<'a> {
    Dummy(PhantomData<&'a [u8]>),
    Rc(Rc<EntropyPool>)
}

#[derive(Clone)]
pub struct XXH3_64<'a> {
    state: C::XXH3_state_t,
    entropy: EntropyRef<'a>
}

impl Default for XXH3_64<'_> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl XXH3_64<'_> {
    #[inline]
    pub fn hash(bytes: &[u8]) -> u64 {
        unsafe { C::XXH3_64bits(bytes.as_ptr() as *const c_void, bytes.len() as u64) }
    }

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

    #[inline]
    pub fn hash_with_entropy(entropy: &EntropyPool, bytes: &[u8]) -> u64 {
        unsafe { Self::hash_with_entropy_buffer(&entropy.entropy, bytes) }
    }

    #[inline]
    pub fn hash_with_seed(seed: u64, bytes: &[u8]) -> u64 {
        unsafe {
            C::XXH3_64bits_withSeed(
                bytes.as_ptr() as *const c_void, bytes.len() as u64, seed)
        }
    }

    #[inline]
    pub fn new() -> XXH3_64<'static> {
        unsafe {
            let mut r = MaybeUninit::<C::XXH3_state_t>::uninit();
            C::XXH3_64bits_reset(r.as_mut_ptr() as *mut C::XXH3_state_t);
            XXH3_64 {
                state: r.assume_init(),
                entropy: EntropyRef::Dummy(PhantomData),
            }
        }
    }

    unsafe fn reset_with_entropy_impl(entropy: &[u8]) -> C::XXH3_state_t {
        assert!(entropy.len() >= (C::XXH3_SECRET_SIZE_MIN) as usize);
        let mut r = MaybeUninit::<C::XXH3_state_t>::uninit();
        C::XXH3_64bits_reset_withSecret(
            r.as_mut_ptr() as *mut C::XXH3_state_t,
            entropy.as_ptr() as *const c_void,
            entropy.len() as u64,
        );

        r.assume_init()
    }

    #[inline]
    pub unsafe fn with_entropy_buffer<'a>(entropy: &'a [u8]) -> XXH3_64<'a> {
        XXH3_64 {
            state: Self::reset_with_entropy_impl(entropy),
            entropy: EntropyRef::Dummy(PhantomData),
        }
    }


    #[inline]
    pub fn with_entropy<'a>(entropy: &EntropyPool) -> XXH3_64<'a> {
        let state = unsafe { Self::reset_with_entropy_impl(&entropy.entropy) };
        XXH3_64 {
            state,
            entropy: EntropyRef::Dummy(PhantomData),
        }
    }

    #[inline]
    pub fn with_entropy_rc(entropy: Rc<EntropyPool>) -> XXH3_64<'static> {
        let state = unsafe { Self::reset_with_entropy_impl(&entropy.entropy) };
        XXH3_64 {
            state,
            entropy: EntropyRef::Rc(entropy),
        }
    }

    #[inline]
    pub fn with_entropy_copy(entropy: &EntropyPool) -> XXH3_64<'static> {
        unsafe {
            let mut r = MaybeUninit::<C::XXH3_state_t>::uninit();
            C::XXH3_XXHRS_64bits_reset_withSecretCopy(
                r.as_mut_ptr() as *mut C::XXH3_state_t,
                entropy.entropy.as_ptr() as *const c_void,
            );
            XXH3_64 {
                state: r.assume_init(),
                entropy: EntropyRef::Dummy(PhantomData),
            }
        }
    }

    #[inline]
    pub fn with_seed(seed: u64) -> XXH3_64<'static> {
        Self::with_entropy_copy(&EntropyPool::with_seed(seed))
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

#[derive(Clone)]
pub struct XXH3_64Hmac {
    state: C::XXH3_XXHRS_64bits_hmac_state
}

impl Default for XXH3_64Hmac {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl XXH3_64Hmac {
    #[inline]
    pub fn hash(bytes: &[u8]) -> u64 {
        Self::hash_with_seed(0, bytes)
    }

    #[inline]
    pub fn hash_with_seed(seed: u64, bytes: &[u8]) -> u64 {
        unsafe { C::XXH3_XXHRS_64bits_hmac(bytes.as_ptr() as *const c_void, bytes.len() as u64, seed) }
    }

    #[inline]
    pub fn new() -> Self {
        Self::with_seed(0)
    }

    #[inline]
    pub fn with_seed(seed: u64) -> Self {
        let mut r = MaybeUninit::<C::XXH3_XXHRS_64bits_hmac_state>::uninit();
        unsafe {
            C::XXH3_XXHRS_64bits_hmac_reset(
                r.as_mut_ptr() as *mut C::XXH3_XXHRS_64bits_hmac_state,
                seed);
            Self {
                state: r.assume_init(),
            }
        }
    }
}

impl Hasher for XXH3_64Hmac {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        unsafe {
            C::XXH3_XXHRS_64bits_hmac_update(
                &mut self.state,
                bytes.as_ptr() as *const c_void,
                bytes.len() as u64,
            );
        }
    }

    #[inline]
    fn finish(&self) -> u64 {
        unsafe { C::XXH3_XXHRS_64bits_hmac_digest(&self.state) }
    }
}

#[derive(Clone)]
pub struct XXH3_128<'a> {
    state: C::XXH3_state_t,
    entropy: EntropyRef<'a>,
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

#[inline]
fn u128_to_xxh128(val: u128) -> C::XXH128_hash_t {
    C::XXH128_hash_t {
        low64: val as u64,
        high64: (val >> 64) as u64
    }
}

impl XXH3_128<'_> {
    #[inline]
    pub fn hash(bytes: &[u8]) -> u128 {
        let r = unsafe { C::XXH3_128bits(bytes.as_ptr() as *const c_void, bytes.len() as u64) };
        xxh128_to_u128(r)
    }

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

    #[inline]
    pub fn hash_with_entropy(entropy: &EntropyPool, bytes: &[u8]) -> u128 {
        unsafe { Self::hash_with_entropy_buffer(&entropy.entropy, bytes) }
    }

    #[inline]
    pub fn hash_with_seed(seed: u64, bytes: &[u8]) -> u128 {
        let r =
            unsafe { C::XXH3_128bits_withSeed(bytes.as_ptr() as *const c_void, bytes.len() as u64, seed) };
        xxh128_to_u128(r)
    }

    #[inline]
    pub fn new() -> XXH3_128<'static> {
        unsafe {
            let mut r = MaybeUninit::<C::XXH3_state_t>::uninit();
            C::XXH3_128bits_reset(r.as_mut_ptr() as *mut C::XXH3_state_t);
            XXH3_128 {
                state: r.assume_init(),
                entropy: EntropyRef::Dummy(PhantomData),
            }
        }
    }

    unsafe fn reset_with_entropy_impl(entropy: &[u8]) -> C::XXH3_state_t {
        assert!(entropy.len() >= (C::XXH3_SECRET_SIZE_MIN) as usize);
        let mut r = MaybeUninit::<C::XXH3_state_t>::uninit();
        C::XXH3_128bits_reset_withSecret(
            r.as_mut_ptr() as *mut C::XXH3_state_t,
            entropy.as_ptr() as *const c_void,
            entropy.len() as u64,
        );

        r.assume_init()
    }

    #[inline]
    pub unsafe fn with_entropy_buffer<'a>(entropy: &'a [u8]) -> XXH3_128<'a> {
        XXH3_128 {
            state: Self::reset_with_entropy_impl(entropy),
            entropy: EntropyRef::Dummy(PhantomData),
        }
    }


    #[inline]
    pub fn with_entropy<'a>(entropy: &EntropyPool) -> XXH3_128<'a> {
        let state = unsafe { Self::reset_with_entropy_impl(&entropy.entropy) };
        XXH3_128 {
            state,
            entropy: EntropyRef::Dummy(PhantomData),
        }
    }

    #[inline]
    pub fn with_entropy_rc(entropy: Rc<EntropyPool>) -> XXH3_128<'static> {
        let state = unsafe { Self::reset_with_entropy_impl(&entropy.entropy) };
        XXH3_128 {
            state,
            entropy: EntropyRef::Rc(entropy),
        }
    }

    #[inline]
    pub fn with_entropy_copy(entropy: &EntropyPool) -> XXH3_128<'static> {
        unsafe {
            let mut r = MaybeUninit::<C::XXH3_state_t>::uninit();
            C::XXH3_XXHRS_128bits_reset_withSecretCopy(
                r.as_mut_ptr() as *mut C::XXH3_state_t,
                entropy.entropy.as_ptr() as *const c_void,
            );
            XXH3_128 {
                state: r.assume_init(),
                entropy: EntropyRef::Dummy(PhantomData),
            }
        }
    }

    #[inline]
    pub fn with_seed(seed: u64) -> XXH3_128<'static> {
        Self::with_entropy_copy(&EntropyPool::with_seed(seed))
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

#[derive(Clone)]
pub struct XXH3_128Hmac {
    state: C::XXH3_XXHRS_128bits_hmac_state
}

impl Default for XXH3_128Hmac {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl XXH3_128Hmac {
    #[inline]
    pub fn hash(bytes: &[u8]) -> u128 {
        Self::hash_with_seed(0, bytes)
    }

    #[inline]
    pub fn hash_with_seed(seed: u128, bytes: &[u8]) -> u128 {
        let r = unsafe { C::XXH3_XXHRS_128bits_hmac(bytes.as_ptr() as *const c_void, bytes.len() as u64, u128_to_xxh128(seed)) };
        xxh128_to_u128(r)
    }

    #[inline]
    pub fn new() -> Self {
        Self::with_seed(0)
    }

    #[inline]
    pub fn with_seed(seed: u128) -> Self {
        let mut r = MaybeUninit::<C::XXH3_XXHRS_128bits_hmac_state>::uninit();
        unsafe {
            C::XXH3_XXHRS_128bits_hmac_reset(
                r.as_mut_ptr() as *mut C::XXH3_XXHRS_128bits_hmac_state,
                u128_to_xxh128(seed));
            Self {
                state: r.assume_init(),
            }
        }
    }

    #[inline]
    pub fn write(&mut self, bytes: &[u8]) {
        unsafe {
            C::XXH3_XXHRS_128bits_hmac_update(
                &mut self.state,
                bytes.as_ptr() as *const c_void,
                bytes.len() as u64,
            );
        }
    }

    #[inline]
    pub fn finish(&self) -> u128 {
        let r = unsafe { C::XXH3_XXHRS_128bits_hmac_digest(&self.state) };
        xxh128_to_u128(r)
    }
}

