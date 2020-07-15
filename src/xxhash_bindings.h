#pragma once
#define XXH_STATIC_LINKING_ONLY 1
#include <stdint.h>
#include "xxhash.h"

extern void XXH3_XXHRS_initCustomSecret(void* customSecret, uint64_t seed64);
extern void XXH3_XXHRS_64bits_reset_withSecretCopy(XXH3_state_t* statePtr, const void* secret);
extern void XXH3_XXHRS_128bits_reset_withSecretCopy(XXH3_state_t* statePtr, const void* secret);
