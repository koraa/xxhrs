use std::{default::Default, hash::Hasher, marker::PhantomData, mem::MaybeUninit, os::raw::c_void, rc::Rc};

use crate::{entropy::EntropyPool, xxhash_bindings as C};

// XXH3_64bits, XXH3_64bits_withSecret, XXH3_64bits_withSeed,
// XXH3_64bits_reset, XXH3_64bits_reset_withSeed, XXH3_64bits_reset_withSecret,
// XXH3_64bits_update, XXH3_64bits_digest
//
// XXH3_128bits, XXH3_128bits_withSecret, XXH3_128bits_withSeed
// XXH3_128bits_reset, XXH3_128bits_reset_withSeed, XXH3_128bits_reset_withSecret,
// XXH3_128bits_update, XXH3_128bits_digest

pub trait XXH3Private<H> {
    fn hash(bytes: &[u8]) -> H;
    fn hash_with_seed(seed: u64, bytes: &[u8]) -> H;
    unsafe fn hash_with_entropy_buffer(entropy: &[u8], bytes: &[u8]) -> H;

    fn new() -> Self;
    fn with_seed(seed: u64) -> Self;
    unsafe fn with_entropy_buffer(entropy: &[u8]) -> Self;
    fn with_entropy_copy(entropy: &EntropyPool) -> Self;

    fn write(&mut self, bytes: &[u8]);
    fn finish(&self) -> H;
}

#[derive(Clone)]
pub enum EntropyRef<'a> {
    Dummy(PhantomData<&'a [u8]>),
    Rc(Rc<EntropyPool>)
}

#[derive(Clone)]
pub struct Buf {
    len: usize,
    data: [u8; 512],
}

impl Buf {
    fn new() -> Self {
        Self {
            len: 0,
            data: [0u8; 512]
        }
    }

    fn write(&mut self, bytes: &[u8]) -> bool {
        if (self.data.len() - self.len) < bytes.len() {
            false
        } else {
            self.data[self.len..][..bytes.len()].copy_from_slice(bytes);
            self.len += bytes.len();
            true
        }
    }
}

#[derive(Clone)]
pub enum BufferedHasher<'a, H, Impl: XXH3Private<H>> {
    Default(Buf, PhantomData<H>),
    Seed(Buf, u64),
    Entropy(Buf, &'a [u8]),
    EntropyRc(Buf, Rc<EntropyPool>),
    Streaming(Impl, EntropyRef<'a>)
}

impl<H, Impl: XXH3Private<H>> BufferedHasher<'_, H, Impl> {
    #[inline]
    pub fn hash(bytes: &[u8]) -> H {
        Impl::hash(bytes)
    }

    #[inline]
    pub fn hash_with_seed(seed: u64, bytes: &[u8]) -> H {
        Impl::hash_with_seed(seed, bytes)
    }

    #[inline]
    pub unsafe fn hash_with_entropy_buffer(entropy: &[u8], bytes: &[u8]) -> H {
        assert!(entropy.len() >= (C::XXH3_SECRET_SIZE_MIN) as usize);
        Impl::hash_with_entropy_buffer(entropy, bytes)
    }

    #[inline]
    pub fn hash_with_entropy(entropy: &EntropyPool, bytes: &[u8]) -> H {
        unsafe {
            Impl::hash_with_entropy_buffer(&entropy.entropy, bytes)
        }
    }

    #[inline]
    pub fn new() -> BufferedHasher<'static, H, Impl> {
        BufferedHasher::Default(Buf::new(), PhantomData)
    }

    #[inline]
    pub fn with_seed(seed: u64) -> BufferedHasher<'static, H, Impl> {
        BufferedHasher::Seed(Buf::new(), seed)
    }

    #[inline]
    pub unsafe fn with_entropy_buffer<'a>(entropy: &'a [u8]) -> BufferedHasher<'a, H, Impl> {
        assert!(entropy.len() >= (C::XXH3_SECRET_SIZE_MIN) as usize);
        BufferedHasher::Entropy(Buf::new(), entropy)
    }

    #[inline]
    pub fn with_entropy<'a>(entropy: &'a EntropyPool) -> BufferedHasher<'a, H, Impl> {
        unsafe {
            Self::with_entropy_buffer(&entropy.entropy)
        }
    }

    #[inline]
    pub fn with_entropy_rc(entropy: Rc<EntropyPool>) -> BufferedHasher<'static, H, Impl> {
        BufferedHasher::EntropyRc(Buf::new(), entropy)
    }

    #[inline]
    pub fn with_entropy_copy(entropy: &EntropyPool) -> BufferedHasher<'static, H, Impl> {
        BufferedHasher::Streaming(Impl::with_entropy_copy(entropy), EntropyRef::Dummy(PhantomData))
    }

    #[inline]
    pub fn write(&mut self, bytes: &[u8]) {
        match self {
            BufferedHasher::Default(ref mut buf, _) => {
                if !buf.write(bytes) {
                    let mut im = Impl::new();
                    im.write(&buf.data[..buf.len]);
                    im.write(bytes);
                    *self = BufferedHasher::Streaming(im, EntropyRef::Dummy(PhantomData))
                }
            }
            BufferedHasher::Seed(ref mut buf, seed) => {
                if !buf.write(bytes) {
                    let mut im = Impl::with_seed(*seed);
                    im.write(&buf.data[..buf.len]);
                    im.write(bytes);
                    *self = BufferedHasher::Streaming(im, EntropyRef::Dummy(PhantomData))
                }
            }
            BufferedHasher::Entropy(ref mut buf, entropy) => {
                if !buf.write(bytes) {
                    let mut im = unsafe {
                        Impl::with_entropy_buffer(entropy)
                    };
                    im.write(&buf.data[..buf.len]);
                    im.write(bytes);
                    *self = BufferedHasher::Streaming(im, EntropyRef::Dummy(PhantomData))
                }
            }
            BufferedHasher::EntropyRc(ref mut buf, entropy) => {
                if !buf.write(bytes) {
                    let mut im = unsafe {
                        Impl::with_entropy_buffer(&entropy.as_ref().entropy)
                    };
                    im.write(&buf.data[..buf.len]);
                    im.write(bytes);
                    *self = BufferedHasher::Streaming(im, EntropyRef::Rc(entropy.clone()))
                }
            }
            BufferedHasher::Streaming(ref mut im, _) => {
                im.write(bytes)
            }
        }
    }

    #[inline]
    pub fn finish(&self) -> H {
        match self {
            BufferedHasher::Default(ref buf, _) => Self::hash(&buf.data),
            BufferedHasher::Seed(ref buf, seed) => Self::hash_with_seed(*seed, &buf.data),
            BufferedHasher::Entropy(ref buf, entropy) => unsafe {
                Self::hash_with_entropy_buffer(entropy, &buf.data)
            },
            BufferedHasher::EntropyRc(ref buf, entropy) => unsafe {
                Self::hash_with_entropy_buffer(&entropy.as_ref().entropy, &buf.data)
            },
            BufferedHasher::Streaming(ref im, _) => im.finish()
        }
    }
}

impl<H, Impl: XXH3Private<H>> Default for BufferedHasher<'_, H, Impl> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Impl: XXH3Private<u64>> Hasher for BufferedHasher<'_, u64, Impl> {
    fn write(&mut self, bytes: &[u8]) {
        Self::write(self, bytes)
    }

    fn finish(&self) -> u64 {
        Self::finish(&self)
    }
}

#[derive(Clone)]
pub struct XXH3_64Impl {
    state: C::XXH3_state_t,
}

impl XXH3Private<u64> for XXH3_64Impl {
    #[inline]
    fn hash(bytes: &[u8]) -> u64 {
        unsafe { C::XXH3_64bits(bytes.as_ptr() as *const c_void, bytes.len() as u64) }
    }

    #[inline]
    fn hash_with_seed(seed: u64, bytes: &[u8]) -> u64 {
        unsafe {
            C::XXH3_64bits_withSeed(
                bytes.as_ptr() as *const c_void, bytes.len() as u64, seed)
        }
    }

    #[inline]
    unsafe fn hash_with_entropy_buffer(entropy: &[u8], bytes: &[u8]) -> u64 {
        C::XXH3_64bits_withSecret(
            bytes.as_ptr() as *const c_void,
            bytes.len() as u64,
            entropy.as_ptr() as *const c_void,
            entropy.len() as u64,
        )
    }

    #[inline]
    fn new() -> Self {
        unsafe {
            let mut r = MaybeUninit::<C::XXH3_state_t>::uninit();
            C::XXH3_64bits_reset(r.as_mut_ptr() as *mut C::XXH3_state_t);
            Self {
                state: r.assume_init(),
            }
        }
    }

    #[inline]
    fn with_seed(seed: u64) -> Self {
        unsafe {
            let mut r = MaybeUninit::<C::XXH3_state_t>::uninit();
            C::XXH3_64bits_reset_withSeed(
                r.as_mut_ptr() as *mut C::XXH3_state_t,
                seed,
            );
            Self {
                state: r.assume_init(),
            }
        }
    }

    #[inline]
    unsafe fn with_entropy_buffer(entropy: &[u8]) -> Self {
        assert!(entropy.len() >= (C::XXH3_SECRET_SIZE_MIN) as usize);
        let mut r = MaybeUninit::<C::XXH3_state_t>::uninit();
        C::XXH3_64bits_reset_withSecret(
            r.as_mut_ptr() as *mut C::XXH3_state_t,
            entropy.as_ptr() as *const c_void,
            entropy.len() as u64,
        );
        Self {
            state: r.assume_init(),
        }
    }

    #[inline]
    fn with_entropy_copy(entropy: &EntropyPool) -> Self {
        unsafe {
            let mut r = MaybeUninit::<C::XXH3_state_t>::uninit();
            C::XXH3_XXHRS_64bits_reset_withSecretCopy(
                r.as_mut_ptr() as *mut C::XXH3_state_t,
                entropy.entropy.as_ptr() as *const c_void,
            );
            Self {
                state: r.assume_init(),
            }
        }
    }

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
pub struct XXH3_128Impl {
    state: C::XXH3_state_t
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

impl XXH3Private<u128> for XXH3_128Impl {
    #[inline]
    fn hash(bytes: &[u8]) -> u128 {
        let r = unsafe { C::XXH3_128bits(bytes.as_ptr() as *const c_void, bytes.len() as u64) };
        xxh128_to_u128(r)
    }

    #[inline]
    unsafe fn hash_with_entropy_buffer(entropy: &[u8], bytes: &[u8]) -> u128 {
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
    fn hash_with_seed(seed: u64, bytes: &[u8]) -> u128 {
        let r = unsafe { C::XXH3_128bits_withSeed(bytes.as_ptr() as *const c_void, bytes.len() as u64, seed) };
        xxh128_to_u128(r)
    }

    #[inline]
    fn new() -> Self {
        unsafe {
            let mut r = MaybeUninit::<C::XXH3_state_t>::uninit();
            C::XXH3_128bits_reset(r.as_mut_ptr() as *mut C::XXH3_state_t);
            Self {
                state: r.assume_init(),
            }
        }
    }

    #[inline]
    fn with_seed(seed: u64) -> Self {
        unsafe {
            let mut r = MaybeUninit::<C::XXH3_state_t>::uninit();
            C::XXH3_128bits_reset_withSeed(
                r.as_mut_ptr() as *mut C::XXH3_state_t,
                seed,
            );
            Self {
                state: r.assume_init(),
            }
        }
    }

    #[inline]
    unsafe fn with_entropy_buffer(entropy: &[u8]) -> Self {
        assert!(entropy.len() >= (C::XXH3_SECRET_SIZE_MIN) as usize);
        let mut r = MaybeUninit::<C::XXH3_state_t>::uninit();
        C::XXH3_128bits_reset_withSecret(
            r.as_mut_ptr() as *mut C::XXH3_state_t,
            entropy.as_ptr() as *const c_void,
            entropy.len() as u64,
        );
        Self {
            state: r.assume_init()
        }
    }

    #[inline]
    fn with_entropy_copy(entropy: &EntropyPool) -> Self {
        unsafe {
            let mut r = MaybeUninit::<C::XXH3_state_t>::uninit();
            C::XXH3_XXHRS_128bits_reset_withSecretCopy(
                r.as_mut_ptr() as *mut C::XXH3_state_t,
                entropy.entropy.as_ptr() as *const c_void,
            );
            Self {
                state: r.assume_init(),
            }
        }
    }

    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        unsafe {
            C::XXH3_128bits_update(
                &mut self.state,
                bytes.as_ptr() as *const c_void,
                bytes.len() as u64,
            );
        }
    }

    #[inline]
    fn finish(&self) -> u128 {
        let r = unsafe { C::XXH3_128bits_digest(&self.state) };
        xxh128_to_u128(r)
    }
}

pub type XXH3_64<'a> = BufferedHasher<'a, u64, XXH3_64Impl>;
pub type XXH3_128<'a> = BufferedHasher<'a, u128, XXH3_128Impl>;

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

