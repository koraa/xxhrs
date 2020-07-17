# xxhrs

Bindings to the xxhash C library. Covers the old xxhash functions as well as
the new xxh3 hash function.

## Use cases?

This was written mainly so xxh3 can be evaluated for use in rust. If you just
need an xxhash implementation, you can use [twox](https://crates.io/crates/twox-hash),
if you want a fast hash function to use in hash tables you probably want [ahash](https://crates.io/crates/ahash).

Currently xxh3 is still experimental and it's output can change, however
as soon as it's implementation has stabilized, it's hash output will remain
consistent across processes & computers.

After that has happened, possible use cases for this crate are:

* You specifically need a xxh3 implementation
* You need high performance and one shot hashing is OK (you probably want xxh3_64)
* You need high performance and you are hashing particularly long inputs (thousands of KB, again xxh3_64 is what you want)
* You need a 128 bit hash function

Note that if you are using xxhrs for performance, you should probably create benchmarks.

## Usage

Cargo.toml

```toml
[dependencies]
# Random entropy is enabled by default; it enables RandomState*
# and EntropyPool::randomize()
xxhrs = { version = "1.0.2", features = ["random_entriopy"] }
```

```rust
use std::{collections::HashMap, hash::Hasher};
use xxhrs::{
  RandomStateXXH64, RandomStateXXH3_64, XXH32, XXH64,
  XXH3_64, XXH3_128, EntropyPool
};

// Old XXHash 64 bit version
let mut h = HashMap::<i32, &str, RandomStateXXH64>::default();
h.insert(42, "the answer");
assert_eq!(h.get(&42), Some(&"the answer"));

// XXH3 64 bit version
let mut h = HashMap::<i32, &str, RandomStateXXH64>::default();
h.insert(42, "the answer");
assert_eq!(h.get(&42), Some(&"the answer"));

// XXHash 32 bit without seed, one shot hashing
assert_eq!(XXH32::hash(b"MyData"), 1695511942);

// XXHash 64 bit with seed, one shot hashing
assert_eq!(XXH64::hash_with_seed(1234, b"MyData"), 4228889600861627182);

// XXH3 64 bit version, streaming hashing, with seed
let mut h = XXH3_64::with_seed(1234);
h.write(b"MyFirstData");
h.write(b"MySecondData");
assert_eq!(h.finish(), 8235025456677196530);

// XXH3 128 bit version, straming hashing, with custom key
let entropy = EntropyPool::with_key(b"My Custom Key!"); // Can be reused for extra performance!
let mut h = XXH3_128::with_entropy(&entropy);
h.write(b"MyFirstData");
h.write(b"MySecondData");
assert_eq!(h.finish(), 49549903637678458428443811344187957401);
```

## Testing

```bash
$ cargo test --all-features
$ cargo test --no-default-features
```

## License

Copyright © (C) 2020, Karolin Varner. All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
Neither the name of the Karolin Varner nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL Softwear, BV BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
