//! clap [Args](clap::Args) for telos configuration

use reth_telos_rpc::eth::telos_client::TelosClientArgs;
use crate::{DEFAULT_MAX_EXECUTE_BLOCK_BATCH_SIZE, DEFAULT_MEMORY_BLOCK_BUFFER_TARGET, DEFAULT_PERSISTENCE_THRESHOLD};

#[derive(Debug, Clone, Default, PartialEq, Eq, clap::Args)]
#[clap(next_help_heading = "Telos")]
/// Telos arguments
pub struct TelosArgs {
    /// TelosZero endpoint to use for API calls (send_transaction, get gas price from table)
    #[arg(long = "telos.telos_endpoint", value_name = "HTTP_URL")]
    pub telos_endpoint: Option<String>,

    /// Signer account name
    #[arg(long = "telos.signer_account")]
    pub signer_account: Option<String>,

    /// Signer permission name
    #[arg(long = "telos.signer_permission")]
    pub signer_permission: Option<String>,

    /// Signer private key
    #[arg(long = "telos.signer_key")]
    pub signer_key: Option<String>,

    /// Seconds to cache gas price
    #[arg(long = "telos.gas_cache_seconds")]
    pub gas_cache_seconds: Option<u32>,

    /// Enable the engine2 experimental features on telos-reth binary
    #[arg(long = "engine.experimental", default_value = "false")]
    pub experimental: bool,

    /// Configure persistence threshold for engine experimental.
    #[arg(long = "engine.persistence-threshold", requires = "experimental", default_value_t = DEFAULT_PERSISTENCE_THRESHOLD)]
    pub persistence_threshold: u64,

    /// Configure the target number of blocks to keep in memory.
    #[arg(long = "engine.memory-block-buffer-target", requires = "experimental", default_value_t = DEFAULT_MEMORY_BLOCK_BUFFER_TARGET)]
    pub memory_block_buffer_target: u64,

    /// Maximum number of blocks to execute sequentially in a batch.
    ///
    /// This is used as a cutoff to prevent long-running sequential block execution when we receive
    /// a batch of downloaded blocks.
    #[arg(long = "engine.max-execute-block-batch-size", requires = "experimental", default_value_t = DEFAULT_MAX_EXECUTE_BLOCK_BATCH_SIZE)]
    pub max_execute_block_batch_size: usize,

    /// Enable Two-way storage compare between reth and telos
    #[arg(long = "telos.two_way_storage_compare", default_value = "false")]
    pub two_way_storage_compare: bool,

    /// Block delta between native and EVM
    #[arg(long = "telos.block_delta")]
    pub block_delta: Option<u32>,
}

impl From<TelosArgs> for TelosClientArgs {
    fn from(args: TelosArgs) -> Self {
        TelosClientArgs {
            telos_endpoint: args.telos_endpoint,
            signer_account: args.signer_account,
            signer_permission: args.signer_permission,
            signer_key: args.signer_key,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{Args, Parser};

    /// A helper type to parse Args more easily
    #[derive(Parser)]
    struct CommandParser<T: Args> {
        #[clap(flatten)]
        args: T,
    }

    #[test]
    fn test_parse_database_args() {
        let default_args = TelosArgs::default();
        let args = CommandParser::<TelosArgs>::parse_from(["reth"]).args;
        assert_eq!(args, default_args);
    }
}
