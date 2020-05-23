// c++ src/gen_fixture_hashes.cc --std=c++17 -Wall -Wextra -Wpedantic -o src/gen_fixture_hashes -Ivendor/xxhash && src/gen_fixture_hashes
#define XXH_STATIC_LINKING_ONLY 1
#define XXH_INLINE_ALL 1
#include <cassert>
#include <cstdint>
#include <utility>
#include <string>
#include <vector>
#include <iomanip>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <xxhash.h>

namespace fs = std::filesystem;

std::vector<uint8_t> read_file(std::string filename) {
  std::ifstream file{filename, std::ios::binary | std::ios::ate};
  std::vector<uint8_t> r;
  r.resize(file.tellg());
  file.seekg(0, std::ios::beg);
  file.read((char*)std::data(r), std::size(r));
  assert(file.gcount() == (ssize_t)std::size(r));
  return r;
}

void pt(const char *name, uint32_t val) {
  std::cout << "const " << name << " :  u32 = 0x"
    << std::hex << std::setfill('0') << std::setw(8) << val << ";\n";
}

void pt(const char *name, uint64_t val) {
  std::cout << "const " << name << " :  u64 = 0x"
    << std::hex << std::setfill('0') << std::setw(16) << val << ";\n";
}

void pt(const char *name, const XXH128_hash_t &val) {
  std::cout << "const " << name << " : u128 = 0x"
    << std::hex << std::setfill('0')
    << std::setw(16) << val.high64
    << std::setw(16) << val.low64 << ";\n";
}

int main(int argc, const char **argv) {
  assert(argc > 0);

  fs::current_path(fs::canonical(fs::path{argv[0]}).parent_path());

  uint32_t seed32 = 0xf7649871;
  uint64_t seed64 = 0x06cd630df7649871;

  const std::vector<uint8_t>
    data = read_file("fixtures/data"),
    entropy = read_file("fixtures/secret_entropy");
  const uint8_t *d = std::data(data), *kd = std::data(entropy);
  size_t s = std::size(data), ks = std::size(entropy);

  pt("SEED32", seed32);
  pt("SEED64", seed64);
  pt("XXH32_HASH     ", XXH32(d, s, 0));
  pt("XXH32_SEEDED   ", XXH32(d, s, seed32));
  pt("XXH64_HASH     ", XXH64(d, s, 0));
  pt("XXH64_SEEDED   ", XXH64(d, s, seed64));
  pt("XXH3_64_HASH   ", XXH3_64bits(d, s));
  pt("XXH3_64_SEEDED ", XXH3_64bits_withSeed(d, s, seed64));
  pt("XXH3_64_KEYED  ", XXH3_64bits_withSecret(d, s, kd, ks));
  pt("XXH3_128_HASH  ", XXH3_128bits(d, s));
  pt("XXH3_128_SEEDED", XXH3_128bits_withSeed(d, s, seed64));
  pt("XXH3_128_KEYED ", XXH3_128bits_withSecret(d, s, kd, ks));

  return 0;
}
