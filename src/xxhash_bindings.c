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
