#[cfg(doctest)]
#[macro_use]
extern crate doc_comment;

mod xxhash_bindings;
mod xxhash;
mod xxh3;
mod entropy;
mod buildhash;

#[cfg(test)]
mod tests;

#[cfg(doctest)]
doctest!("../readme.md");

pub use xxhash::*;
pub use xxh3::*;
pub use entropy::*;
pub use buildhash::*;
