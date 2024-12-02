use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use antelope::api::client::{APIClient, DefaultProvider};
use telos_consensus_client::client::ConsensusClient;
use telos_consensus_client::config::{AppConfig, CliArgs};
use telos_consensus_client::main_utils::build_consensus_client;
use telos_translator_rs::translator::Translator;
use telos_translator_rs::types::translator_types::ChainId;
use testcontainers::{ContainerAsync, GenericImage};
use testcontainers::core::ContainerPort::Tcp;
use testcontainers::runners::AsyncRunner;
use reth::args::RpcServerArgs;
use reth::builder::NodeConfig;
use reth_chainspec::{ChainSpec, ChainSpecBuilder, TEVMTESTNET};

#[derive(Debug)]
pub struct TelosRethNodeHandle {
    pub execution_port: u16,
    pub jwt_secret: String,
}


pub const CONTAINER_NAME: &str = "ghcr.io/telosnetwork/testcontainer-nodeos-evm";
pub const CONTAINER_NAME_LITE: &str = "guilledk/testcontainer-nodeos-evm-lite";

pub const CONTAINER_TAG: &str =
    "v0.1.11@sha256:d138f2e08db108d5d420b4db99a57fb9d45a3ee3e0f0faa7d4c4a065f7f018ce";
pub const CONTAINER_TAG_LITE: &str =
    "latest@sha256:e91304655bca4b190af5c7d1bbdd86ba26ae927c43fe82bdc36edfad24e022cb";

// This is the last block in the container, after this block the node is done syncing and is running live
pub const CONTAINER_LAST_EVM_BLOCK: u64 = 1010;
pub const CONTAINER_LAST_EVM_BLOCK_LITE: u64 = 37;

pub async fn start_ship(name: &str, tag: &str) -> ContainerAsync<GenericImage> {
    // Change this container to a local image if using new ship data,
    //   then make sure to update the ship data in the testcontainer-nodeos-evm repo and build a new version

    // The tag for this image needs to come from the Github packages UI, under the "OS/Arch" tab
    //   and should be the tag for linux/amd64
    let container: ContainerAsync<GenericImage> =
        GenericImage::new(name, tag)
            .with_exposed_port(Tcp(8888))
            .with_exposed_port(Tcp(18999))
            .start()
            .await
            .unwrap();

    let port_8888 = container.get_host_port_ipv4(8888).await.unwrap();

    let api_base_url = format!("http://localhost:{port_8888}");
    let api_client = APIClient::<DefaultProvider>::default_provider(api_base_url, Some(1)).unwrap();

    let mut last_block = 0;

    loop {
        let Ok(info) = api_client.v1_chain.get_info().await else {
            println!("Waiting for telos node to produce blocks...");
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            continue;
        };
        if last_block != 0 && info.head_block_num > last_block {
            break;
        }
        last_block = info.head_block_num;
    }

    container
}

pub fn init_reth() -> eyre::Result<(NodeConfig<ChainSpec>, String)> {
    let chain_spec = Arc::new(
        ChainSpecBuilder::default()
            .chain(TEVMTESTNET.chain)
            .genesis(TEVMTESTNET.genesis.clone())
            .frontier_activated()
            .homestead_activated()
            .tangerine_whistle_activated()
            .spurious_dragon_activated()
            .byzantium_activated()
            .constantinople_activated()
            .petersburg_activated()
            .istanbul_activated()
            .berlin_activated()
            .build(),
    );

    let mut rpc_config = RpcServerArgs::default().with_unused_ports().with_http();
    rpc_config.auth_jwtsecret = Some(PathBuf::from("tests/assets/jwt.hex"));

    // Node setup
    let node_config = NodeConfig::test().with_chain(chain_spec).with_rpc(rpc_config.clone());

    let jwt = fs::read_to_string(node_config.rpc.auth_jwtsecret.clone().unwrap())?;
    Ok((node_config, jwt))
}

pub async fn build_consensus_and_translator(
    reth_handle: crate::TelosRethNodeHandle,
    ship_port: u16,
    chain_port: u16,
) -> (ConsensusClient, Translator) {
    let config = AppConfig {
        log_level: "debug".to_string(),
        chain_id: ChainId(41),
        execution_endpoint: format!("http://localhost:{}", reth_handle.execution_port),
        jwt_secret: reth_handle.jwt_secret,
        ship_endpoint: format!("ws://localhost:{ship_port}"),
        chain_endpoint: format!("http://localhost:{chain_port}"),
        batch_size: 1,
        prev_hash: "b25034033c9ca7a40e879ddcc29cf69071a22df06688b5fe8cc2d68b4e0528f9".to_string(),
        validate_hash: None,
        evm_start_block: 1,
        // TODO: Determine a good stop block and test it here
        evm_stop_block: None,
        data_path: "temp/db".to_string(),
        block_checkpoint_interval: 1000,
        maximum_sync_range: 100000,
        latest_blocks_in_db_num: 100,
        max_retry: None,
        retry_interval: None,
    };

    let cli_args = CliArgs { config: "".to_string(), clean: true };

    let c = build_consensus_client(&cli_args, config).await.unwrap();
    let translator = Translator::new((&c.config).into());

    (c, translator)
}
