use alloy_provider::{Provider, ProviderBuilder};
use reqwest::Url;
use reth::{
    builder::NodeBuilder,
    tasks::TaskManager,
};
use reth_e2e_test_utils::node::NodeTestContext;
use reth_node_telos::{TelosArgs, TelosNode};
use reth_telos_rpc::TelosClient;
use std::time::Duration;
use telos_translator_rs::block::TelosEVMBlock;
use testcontainers::runners::AsyncRunner;
use tokio::sync::mpsc;
use crate::utils::runners::{build_consensus_and_translator, CONTAINER_LAST_EVM_BLOCK, CONTAINER_NAME, CONTAINER_TAG, init_reth, start_ship, TelosRethNodeHandle};

pub mod live_test_runner;
pub mod utils;


#[tokio::test]
async fn testing_chain_sync() {
    tracing_subscriber::fmt::init();

    println!("Starting test node");
    let container = start_ship(CONTAINER_NAME, CONTAINER_TAG).await;
    let chain_port = container.get_host_port_ipv4(8888).await.unwrap();
    let ship_port = container.get_host_port_ipv4(18999).await.unwrap();

    let (node_config, jwt_secret) = init_reth().unwrap();

    let exec = TaskManager::current();
    let exec = exec.executor();

    reth_tracing::init_test_tracing();

    let telos_args = TelosArgs {
        telos_endpoint: Some(format!("http://localhost:{chain_port}")),
        signer_account: Some("rpc.evm".to_string()),
        signer_permission: Some("active".to_string()),
        signer_key: Some("5Jr65kdYmn33C3UabzhmWDm2PuqbRfPuDStts3ZFNSBLM7TqaiL".to_string()),
        gas_cache_seconds: None,
        experimental: false,
        persistence_threshold: 0,
        memory_block_buffer_target: 1,
        max_execute_block_batch_size: 100,
        two_way_storage_compare: false,
        block_delta: None,
    };

    let node_handle = NodeBuilder::new(node_config.clone())
        .testing_node(exec)
        .node(TelosNode::new(telos_args.clone()))
        .extend_rpc_modules(move |ctx| {
            if telos_args.telos_endpoint.is_some() {
                ctx.registry.eth_api().set_telos_client(TelosClient::new(telos_args.into()));
            }

            Ok(())
        })
        .launch()
        .await
        .unwrap();

    let execution_port = node_handle.node.auth_server_handle().local_addr().port();
    let rpc_port = node_handle.node.rpc_server_handles.rpc.http_local_addr().unwrap().port();
    let reth_handle = TelosRethNodeHandle { execution_port, jwt_secret };
    println!("Starting Reth on RPC port {}!", rpc_port);
    let _ = NodeTestContext::new(node_handle.node.clone()).await.unwrap();
    println!("Starting consensus on RPC port {}!", rpc_port);
    let (client, translator) =
        build_consensus_and_translator(reth_handle, ship_port, chain_port).await;

    let consensus_shutdown = client.shutdown_handle();
    let translator_shutdown = translator.shutdown_handle();

    let (block_sender, block_receiver) = mpsc::channel::<TelosEVMBlock>(1000);

    println!("Telos consensus client starting, awaiting result...");
    let client_handle = tokio::spawn(client.run(block_receiver));

    println!("Telos translator client is starting...");
    let translator_handle = tokio::spawn(translator.launch(Some(block_sender)));

    let rpc_url = Url::from(format!("http://localhost:{}", rpc_port).parse().unwrap());
    let provider = ProviderBuilder::new().on_http(rpc_url.clone());

    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let latest_block = provider.get_block_number().await.unwrap();
        println!("Latest block: {latest_block}");
        if client_handle.is_finished() {
            _ = translator_shutdown.shutdown().await.unwrap();
            break;
        }
        if latest_block > CONTAINER_LAST_EVM_BLOCK {
            break;
        }
    }

    live_test_runner::run_tests(
        &rpc_url.clone().to_string(),
        "87ef69a835f8cd0c44ab99b7609a20b2ca7f1c8470af4f0e5b44db927d542084",
    )
    .await;

    _ = translator_shutdown.shutdown().await.unwrap();
    _ = consensus_shutdown.shutdown().await.unwrap();

    println!("Client shutdown done.");

    _ = tokio::join!(client_handle, translator_handle);
    println!("Translator shutdown done.");
}
