#[cfg(doctest)]
#[macro_use]
extern crate doc_comment;

mod buildhash;
mod entropy;
mod xxh3;
mod xxhash;
mod xxhash_bindings;

#[cfg(test)]
mod tests;

#[cfg(doctest)]
doctest!("../readme.md");

pub use buildhash::*;
pub use entropy::*;
pub use xxh3::*;
pub use xxhash::*;
