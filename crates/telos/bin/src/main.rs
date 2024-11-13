#![allow(missing_docs)]

#[global_allocator]
static ALLOC: reth_cli_util::allocator::Allocator = reth_cli_util::allocator::new_allocator();

use clap::Parser;
use tracing::{error, info, warn};
use reth::args::utils::EthereumChainSpecParser;
use reth_node_builder::{engine_tree_config::TreeConfig, EngineNodeLauncher};
use reth::cli::Cli;
use reth_node_telos::{TelosArgs, TelosNode};
use reth_node_telos::node::TelosAddOns;
use reth_provider::providers::BlockchainProvider2;
use reth_telos_rpc::TelosClient;
use reth::primitives::BlockId;
use reth::rpc::types::BlockNumberOrTag;
use reth_provider::{DatabaseProviderFactory, StateProviderFactory};
use reth_db::{PlainAccountState, PlainStorageState};


#[cfg(feature = "telos")]
fn main() {
    use reth_provider::BlockNumReader;

    reth_cli_util::sigsegv_handler::install();

    // Enable backtraces unless a RUST_BACKTRACE value has already been explicitly provided.
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }

    if let Err(err) = Cli::<EthereumChainSpecParser, TelosArgs>::parse().run(|builder, telos_args| async move {
        match telos_args.experimental {
            true => {
                let engine_tree_config = TreeConfig::default()
                    .with_persistence_threshold(telos_args.persistence_threshold)
                    .with_max_execute_block_batch_size(telos_args.max_execute_block_batch_size)
                    .with_memory_block_buffer_target(telos_args.memory_block_buffer_target);
                let handle = builder
                    .with_types_and_provider::<TelosNode, BlockchainProvider2<_>>()
                    .with_components(TelosNode::components())
                    .with_add_ons::<TelosAddOns>()
                    .launch_with_fn(|builder| {
                        let launcher = EngineNodeLauncher::new(
                            builder.task_executor().clone(),
                            builder.config().datadir(),
                            engine_tree_config,
                        );
                        builder.launch_with(launcher)
                    })
                    .await?;
                handle.node_exit_future.await
            },
            false => {
                let two_way_storage_compare = telos_args.two_way_storage_compare.clone();
                let telos_rpc = telos_args.telos_endpoint.clone();
                let block_delta = telos_args.block_delta.clone();

                let handle = builder
                    .node(TelosNode::new(telos_args.clone()))
                    .extend_rpc_modules(move |ctx| {
                        if telos_args.telos_endpoint.is_some() {
                            ctx.registry
                                .eth_api()
                                .set_telos_client(TelosClient::new(telos_args.into()));
                        }

                        Ok(())
                    })
                    .launch()
                    .await?;

                match two_way_storage_compare {
                    true => {
                        if telos_rpc.is_none() {
                            warn!("Telos RPC Endpoint is not specified, skipping two-way storage compare");
                        } else if block_delta.is_none() {
                            warn!("Block delta is not specified, skipping two-way storage compare");
                        } else {
                            info!("Fetching account and accountstate from Telos native RPC (Can take a long time)...");

                            let (account_table, accountstate_table, block_number) = reth_node_telos::two_way_storage_compare::get_telos_tables(telos_rpc.unwrap().as_str(), block_delta.unwrap()).await;

                            if block_number.as_u64().unwrap() <= handle.node.provider.best_block_number().unwrap() {
                                info!("Two-way comparing state (Reth vs. Telos) at height: {:?}", block_number);

                                let state_at_specific_height = handle.node.provider.state_by_block_id(BlockId::Number(BlockNumberOrTag::Number(block_number.as_u64().unwrap()))).unwrap();
                                let plain_account_state = handle.node.provider.database_provider_ro().unwrap().table::<PlainAccountState>().unwrap();
                                let plain_storage_state = handle.node.provider.database_provider_ro().unwrap().table::<PlainStorageState>().unwrap();

                                let match_counter = reth_node_telos::two_way_storage_compare::two_side_state_compare(account_table, accountstate_table, state_at_specific_height, plain_account_state, plain_storage_state).await;
                                match_counter.print();

                                info!("Comparing done");
                            } else {
                                error!("Nodeos is ahead of reth, failed to compare state");
                            }
                        }
                    }
                    _ => {}
                }

                handle.node_exit_future.await
            }
        }
    }) {
        eprintln!("Error: {err:?}");
        std::process::exit(1);
    }
}
