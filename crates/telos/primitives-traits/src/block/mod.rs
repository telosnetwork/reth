//! Block-related consensus types.

mod header;
pub use header::TelosHeader;

#[cfg(all(feature = "serde", feature = "serde-bincode-compat"))]
pub(crate) use header::serde_bincode_compat;