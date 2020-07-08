#define XXH_IMPLEMENTATION
#include <stdint.h>
#include "xxhash_bindings.h"

void XXH3_XXHRS_initCustomSecret(uint8_t *customSecret, uint64_t seed64) {
  XXH3_initCustomSecret(customSecret, seed64);
}

void XXH3_XXHRS_64bits_reset_withSecretCopy(XXH3_state_t* statePtr, const void* secret)  {
  XXH3_64bits_reset_internal(statePtr, 0, secret, XXH_SECRET_DEFAULT_SIZE);
  memcpy(statePtr->customSecret, secret, XXH_SECRET_DEFAULT_SIZE);
  statePtr->extSecret = NULL;
}

void XXH3_XXHRS_128bits_reset_withSecretCopy(XXH3_state_t* statePtr, const void* secret)  {
  XXH3_128bits_reset_internal(statePtr, 0, secret, XXH_SECRET_DEFAULT_SIZE);
  memcpy(statePtr->customSecret, secret, XXH_SECRET_DEFAULT_SIZE);
  statePtr->extSecret = NULL;
}

XXH64_hash_t XXH3_XXHRS_64bits_hmac(const void *in, size_t len, XXH64_hash_t key) {
  XXH64_hash_t key1, state2[2];
  key1 = key ^ 0x5c5c5c5c5c5c5c5c;
  state2[0] = key ^ 0x3636363636363636;

  if (XXH_likely(len < XXH3_MIDSIZE_MAX)) {
    char state[XXH3_MIDSIZE_MAX+8];
    memcpy(state, &key1, sizeof(XXH64_hash_t));
    memcpy(state + sizeof(XXH64_hash_t), in, len);
    state2[1] = XXH3_64bits(state, len + sizeof(XXH64_hash_t));
  } else {
    XXH3_state_t state;
    XXH3_64bits_reset(&state);
    XXH3_64bits_update(&state, &key1, sizeof(XXH64_hash_t));
    XXH3_64bits_update(&state, in, len);
    state2[1] = XXH3_64bits_digest(&state);
  }

  return XXH3_64bits(&state2, sizeof(XXH64_hash_t) * sizeof(state2));
}

XXH128_hash_t XXH3_XXHRS_128bits_hmac(const void *in, size_t len, XXH128_hash_t key) {
  XXH128_hash_t key1, state2[2];
  key1.low64 = key.low64   ^ 0x5c5c5c5c5c5c5c5c;
  key1.high64 = key.high64 ^ 0x5c5c5c5c5c5c5c5c;
  state2[0].low64 = key.low64   ^ 0x3636363636363636;
  state2[0].high64 = key.high64 ^ 0x3636363636363636;

  if (XXH_likely(len < XXH3_MIDSIZE_MAX)) {
    char state[XXH3_MIDSIZE_MAX+8];
    memcpy(state, &key1, sizeof(XXH128_hash_t));
    memcpy(state + sizeof(XXH128_hash_t), in, len);
    state2[1] = XXH3_128bits(state, len + sizeof(XXH128_hash_t));
  } else {
    XXH3_state_t state;
    XXH3_128bits_reset(&state);
    XXH3_128bits_update(&state, &key1, sizeof(XXH128_hash_t));
    XXH3_128bits_update(&state, in, len);
    state2[1] = XXH3_128bits_digest(&state);
  }

  return XXH3_128bits(&state2, sizeof(XXH128_hash_t) * sizeof(state2));
}

void XXH3_XXHRS_64bits_hmac_reset(struct XXH3_XXHRS_64bits_hmac_state *state, XXH64_hash_t key) {
  XXH3_64bits_reset(&state->xxh3);
  XXH64_hash_t inner_key = key ^ 0x5c5c5c5c5c5c5c5c;
  XXH3_64bits_update(&state->xxh3, &inner_key, sizeof(XXH64_hash_t));
  state->outer_key = key ^ 0x3636363636363636;
}

void XXH3_XXHRS_64bits_hmac_update(struct XXH3_XXHRS_64bits_hmac_state *state, const void* input, size_t len) {
  XXH3_64bits_update(&state->xxh3, input, len);
}

XXH64_hash_t XXH3_XXHRS_64bits_hmac_digest(const struct XXH3_XXHRS_64bits_hmac_state *state) {
  XXH64_hash_t state2[2];
  state2[0] = state->outer_key;
  state2[1] = XXH3_64bits_digest(&state->xxh3);
  return XXH3_64bits(state2, sizeof(XXH64_hash_t) * sizeof(state2));
}

void XXH3_XXHRS_128bits_hmac_reset(struct XXH3_XXHRS_128bits_hmac_state *state, XXH128_hash_t key) {
  XXH3_128bits_reset(&state->xxh3);
  XXH128_hash_t inner_key;
  inner_key.low64 = key.low64   ^ 0x5c5c5c5c5c5c5c5c;
  inner_key.high64 = key.high64 ^ 0x5c5c5c5c5c5c5c5c;
  XXH3_128bits_update(&state->xxh3, &inner_key, sizeof(XXH128_hash_t));
  state->outer_key.low64 = key.low64   ^ 0x3636363636363636;
  state->outer_key.high64 = key.high64 ^ 0x3636363636363636;
}

void XXH3_XXHRS_128bits_hmac_update(struct XXH3_XXHRS_128bits_hmac_state *state, const void* input, size_t len) {
  XXH3_128bits_update(&state->xxh3, input, len);
}

XXH128_hash_t XXH3_XXHRS_128bits_hmac_digest(const struct XXH3_XXHRS_128bits_hmac_state *state) {
  XXH128_hash_t state2[2];
  state2[0] = state->outer_key;
  state2[1] = XXH3_128bits_digest(&state->xxh3);
  return XXH3_128bits(&state2, sizeof(XXH128_hash_t) * sizeof(state2));
}

void XXH3_XXHRS_128bit_hkdf(void* secretBuffer, const void* customSeed, size_t customSeedSize) {
  size_t const segmentSize = sizeof(XXH128_hash_t);
  size_t const nbSegments = XXH_SECRET_DEFAULT_SIZE / segmentSize;
  XXH128_hash_t dat[2];
  dat[0].low64 = dat[0].high64 = dat[1].low64 = dat[1].high64 = 0;
  XXH128_hash_t prk = XXH3_XXHRS_128bits_hmac(customSeed, customSeedSize, dat[0]);
  for (int idx = 0; idx < nbSegments; idx++) {
    dat[1].low64 = idx;
    dat[0] = XXH3_XXHRS_128bits_hmac(&dat, sizeof(XXH128_hash_t) * 2, prk);
    memcpy(&((XXH128_hash_t*)secretBuffer)[idx], dat, sizeof(XXH128_hash_t) * 2);
  }
}
