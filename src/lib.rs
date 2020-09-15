#[cfg(doctest)]
#[macro_use]
extern crate doc_comment;

// C code //

#[allow(non_snake_case)]
mod C;
mod xxhash_bindings;

// Rust code //

#[cfg(feature = "random_entropy")]
mod buildhash;
mod entropy;
mod xxh3;
mod xxhash;

// Tests //

#[cfg(all(test))]
mod tests;

#[cfg(doctest)]
#[cfg(feature = "random_entropy")]
doctest!("../readme.md");

// Exports //

#[cfg(feature = "random_entropy")]
pub use buildhash::*;

pub use entropy::*;
pub use xxh3::*;
pub use xxhash::*;
