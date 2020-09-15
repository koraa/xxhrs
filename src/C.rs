// This pulls in all declarations from C code
// This also strips the random namespace we used to avoid collisions
// if libxxhash is linked against multiple times
pub use crate::xxhash_bindings::{
    xxhrs_equodaeyiejoopibaeva_XXH32 as XXH32,
    xxhrs_equodaeyiejoopibaeva_XXH32_digest as XXH32_digest,
    xxhrs_equodaeyiejoopibaeva_XXH32_reset as XXH32_reset,
    xxhrs_equodaeyiejoopibaeva_XXH32_update as XXH32_update,
    xxhrs_equodaeyiejoopibaeva_XXH3_128bits as XXH3_128bits,
    xxhrs_equodaeyiejoopibaeva_XXH3_128bits_digest as XXH3_128bits_digest,
    xxhrs_equodaeyiejoopibaeva_XXH3_128bits_reset as XXH3_128bits_reset,
    xxhrs_equodaeyiejoopibaeva_XXH3_128bits_reset_withSecret as XXH3_128bits_reset_withSecret,
    xxhrs_equodaeyiejoopibaeva_XXH3_128bits_reset_withSeed as XXH3_128bits_reset_withSeed,
    xxhrs_equodaeyiejoopibaeva_XXH3_128bits_update as XXH3_128bits_update,
    xxhrs_equodaeyiejoopibaeva_XXH3_128bits_withSecret as XXH3_128bits_withSecret,
    xxhrs_equodaeyiejoopibaeva_XXH3_128bits_withSeed as XXH3_128bits_withSeed,
    xxhrs_equodaeyiejoopibaeva_XXH3_64bits as XXH3_64bits,
    xxhrs_equodaeyiejoopibaeva_XXH3_64bits_digest as XXH3_64bits_digest,
    xxhrs_equodaeyiejoopibaeva_XXH3_64bits_reset as XXH3_64bits_reset,
    xxhrs_equodaeyiejoopibaeva_XXH3_64bits_reset_withSecret as XXH3_64bits_reset_withSecret,
    xxhrs_equodaeyiejoopibaeva_XXH3_64bits_reset_withSeed as XXH3_64bits_reset_withSeed,
    xxhrs_equodaeyiejoopibaeva_XXH3_64bits_update as XXH3_64bits_update,
    xxhrs_equodaeyiejoopibaeva_XXH3_64bits_withSecret as XXH3_64bits_withSecret,
    xxhrs_equodaeyiejoopibaeva_XXH3_64bits_withSeed as XXH3_64bits_withSeed,
    xxhrs_equodaeyiejoopibaeva_XXH3_generateSecret as XXH3_generateSecret,
    xxhrs_equodaeyiejoopibaeva_XXH64 as XXH64,
    xxhrs_equodaeyiejoopibaeva_XXH64_digest as XXH64_digest,
    xxhrs_equodaeyiejoopibaeva_XXH64_reset as XXH64_reset,
    xxhrs_equodaeyiejoopibaeva_XXH64_update as XXH64_update,
    xxhrs_equodaeyiejoopibaeva_XXHRS_128bits_reset_withSecretCopy as XXHRS_128bits_reset_withSecretCopy,
    xxhrs_equodaeyiejoopibaeva_XXHRS_64bits_reset_withSecretCopy as XXHRS_64bits_reset_withSecretCopy,
    XXH128_hash_t, XXH32_state_t, XXH3_state_t, XXH64_state_t, XXH3_SECRET_DEFAULT_SIZE,
    XXH3_SECRET_SIZE_MIN,
};
