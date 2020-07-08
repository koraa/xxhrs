#pragma once
#define XXH_STATIC_LINKING_ONLY 1
#include <stdint.h>
#include "xxhash.h"

extern void XXH3_XXHRS_initCustomSecret(uint8_t* customSecret, uint64_t seed64);
extern void XXH3_XXHRS_64bits_reset_withSecretCopy(XXH3_state_t* statePtr, const void* secret);
extern void XXH3_XXHRS_128bits_reset_withSecretCopy(XXH3_state_t* statePtr, const void* secret);

struct XXH3_XXHRS_64bits_hmac_state {
  XXH3_state_t xxh3;
  XXH64_hash_t outer_key;
};
extern XXH64_hash_t XXH3_XXHRS_64bits_hmac(const void*, size_t, XXH64_hash_t);
extern void XXH3_XXHRS_64bits_hmac_reset(struct XXH3_XXHRS_64bits_hmac_state *state, XXH64_hash_t key);
extern void XXH3_XXHRS_64bits_hmac_update(struct XXH3_XXHRS_64bits_hmac_state *state, const void* input, size_t len);
extern XXH64_hash_t XXH3_XXHRS_64bits_hmac_digest(const struct XXH3_XXHRS_64bits_hmac_state *state);

struct XXH3_XXHRS_128bits_hmac_state {
  XXH3_state_t xxh3;
  XXH128_hash_t outer_key;
};
extern XXH128_hash_t XXH3_XXHRS_128bits_hmac(const void*, size_t, XXH128_hash_t);
extern void XXH3_XXHRS_128bits_hmac_reset(struct XXH3_XXHRS_128bits_hmac_state *state, XXH128_hash_t key);
extern void XXH3_XXHRS_128bits_hmac_update(struct XXH3_XXHRS_128bits_hmac_state *state, const void* input, size_t len);
extern XXH128_hash_t XXH3_XXHRS_128bits_hmac_digest(const struct XXH3_XXHRS_128bits_hmac_state *state);

extern void XXH3_XXHRS_128bit_hkdf(void* secretBuffer, const void* customSeed, size_t customSeedSize);
