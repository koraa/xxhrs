#[cfg(doctest)]
#[macro_use]
extern crate doc_comment;

#[cfg(feature = "random_entropy")]
mod buildhash;

mod entropy;
mod xxh3;
mod xxhash;
mod xxhash_bindings;

#[cfg(all(test))]
mod tests;

#[cfg(doctest)]
#[cfg(feature = "random_entropy")]
doctest!("../readme.md");

#[cfg(feature = "random_entropy")]
pub use buildhash::*;

pub use entropy::*;
pub use xxh3::*;
pub use xxhash::*;
