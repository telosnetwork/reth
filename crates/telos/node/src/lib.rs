//! Standalone crate for Telos-specific Reth configuration and builder types.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/paradigmxyz/reth/main/assets/reth-docs.png",
    html_favicon_url = "https://avatars0.githubusercontent.com/u/97369466?s=256",
    issue_tracker_base_url = "https://github.com/telosnetwork/telos-reth/issues/"
)]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

#![cfg(feature = "telos")]

pub mod args;
pub mod node;
pub mod two_way_storage_compare;

pub use crate::args::TelosArgs;
pub use crate::node::TelosNode;

const DEFAULT_PERSISTENCE_THRESHOLD: u64 = 16;
const DEFAULT_MEMORY_BLOCK_BUFFER_TARGET: u64 = 16;
const DEFAULT_MAX_EXECUTE_BLOCK_BATCH_SIZE: usize = 50;