#pragma once
#include <stdint.h>

#define XXH_STATIC_LINKING_ONLY 1
#define XXH_NAMESPACE xxhrs_equodaeyiejoopibaeva_
#include "xxhash.h"

#define XXHRS_CAT(A,B) A##B
#define XXHRS_NAME2(A,B) XXH_CAT(A,B)
#define XXHRS_64bits_reset_withSecretCopy XXHRS_NAME2(XXH_NAMESPACE, XXHRS_64bits_reset_withSecretCopy)
#define XXHRS_128bits_reset_withSecretCopy XXHRS_NAME2(XXH_NAMESPACE, XXHRS_128bits_reset_withSecretCopy)

extern void XXHRS_64bits_reset_withSecretCopy(XXH3_state_t* statePtr, const void* secret);
extern void XXHRS_128bits_reset_withSecretCopy(XXH3_state_t* statePtr, const void* secret);
