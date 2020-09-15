#define XXH_IMPLEMENTATION
#include <stdint.h>
#include "xxhash_bindings.h"

void XXHRS_64bits_reset_withSecretCopy(XXH3_state_t* statePtr, const void* secret)  {
  XXH3_64bits_reset_internal(statePtr, 0, secret, XXH_SECRET_DEFAULT_SIZE);
  memcpy(statePtr->customSecret, secret, XXH_SECRET_DEFAULT_SIZE);
  statePtr->extSecret = NULL;
}

void XXHRS_128bits_reset_withSecretCopy(XXH3_state_t* statePtr, const void* secret)  {
  XXH3_128bits_reset_internal(statePtr, 0, secret, XXH_SECRET_DEFAULT_SIZE);
  memcpy(statePtr->customSecret, secret, XXH_SECRET_DEFAULT_SIZE);
  statePtr->extSecret = NULL;
}
