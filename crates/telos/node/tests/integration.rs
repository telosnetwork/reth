use std::str::FromStr;
use antelope::api::client::{APIClient, DefaultProvider};
use reth::{
    builder::NodeBuilder,
    tasks::TaskManager,
};
use reth_e2e_test_utils::node::NodeTestContext;
use reth_node_telos::{TelosArgs, TelosNode};
use reth_telos_rpc::TelosClient;
use std::time::Duration;
use alloy_network::{Ethereum, EthereumWallet, ReceiptResponse, TransactionBuilder};
use alloy_primitives::{Address, B256, Bytes, keccak256, U256};
use alloy_primitives::hex::FromHex;
use alloy_primitives::TxKind::Create;
use telos_translator_rs::block::TelosEVMBlock;
use tokio::sync::mpsc;
use tracing::{info, warn};
use reth::primitives::BlockId;
use alloy_rpc_types::{AccessList, AccessListItem, BlockTransactionsKind};
use alloy_transport_http::Http;
use antelope::chain::action::PermissionLevel;
use antelope::chain::private_key::PrivateKey;
use antelope::name;
use antelope::chain::name::Name;

pub mod utils;
use crate::utils::cleos_evm::{EOSIO_ADDR, EOSIO_PKEY, EOSIO_WALLET, get_nonce, multi_raw_eth_tx, setrevision_tx, sign_native_tx};
use crate::utils::runners::{build_consensus_and_translator, CONTAINER_LAST_EVM_BLOCK_LITE, CONTAINER_NAME_LITE, CONTAINER_TAG_LITE, init_reth, start_ship, TelosRethNodeHandle};

use alloy_provider::{Identity, Provider, ProviderBuilder, ReqwestProvider};
use alloy_provider::fillers::{FillProvider, JoinFill, WalletFiller};
use alloy_rpc_types::BlockNumberOrTag::Latest;
use alloy_sol_types::{sol, SolEvent};
use reqwest::{Client, Url};
use reth::rpc::types::{TransactionInput, TransactionRequest};

pub type TestProvider = FillProvider<JoinFill<Identity, WalletFiller<EthereumWallet>>, ReqwestProvider, Http<Client>, Ethereum>;

#[tokio::test]
async fn testing_chain_sync() {
    env_logger::builder().is_test(true).try_init().unwrap();

    info!("Starting test node");
    let container = start_ship(CONTAINER_NAME_LITE, CONTAINER_TAG_LITE).await;
    let chain_port = container.get_host_port_ipv4(8888).await.unwrap();
    let ship_port = container.get_host_port_ipv4(18999).await.unwrap();

    let telos_url = format!("http://localhost:{}", chain_port);
    let telos_client = APIClient::<DefaultProvider>::default_provider(telos_url, Some(1)).unwrap();

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
    info!("Starting Reth on RPC port {}!", rpc_port);
    let _ = NodeTestContext::new(node_handle.node.clone()).await.unwrap();
    info!("Starting consensus on RPC port {}!", rpc_port);
    let (client, translator) =
        build_consensus_and_translator(reth_handle, ship_port, chain_port).await;

    let consensus_shutdown = client.shutdown_handle();
    let translator_shutdown = translator.shutdown_handle();

    let (block_sender, block_receiver) = mpsc::channel::<TelosEVMBlock>(1000);

    info!("Telos consensus client starting, awaiting result...");
    let client_handle = tokio::spawn(client.run(block_receiver));

    info!("Telos translator client is starting...");
    let translator_handle = tokio::spawn(translator.launch(Some(block_sender)));

    let rpc_url = Url::from(format!("http://localhost:{}", rpc_port).parse().unwrap());
    let reth_provider = ProviderBuilder::new()
        .wallet(EOSIO_WALLET.clone())
        .on_http(rpc_url.clone());

    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let latest_block = reth_provider.get_block_number().await.unwrap();
        info!("Latest block: {latest_block}");
        if client_handle.is_finished() {
            _ = translator_shutdown.shutdown().await.unwrap();
            break;
        }
        if latest_block > CONTAINER_LAST_EVM_BLOCK_LITE {
            break;
        }
    }

    run_tests(&telos_client, &reth_provider).await;

    _ = translator_shutdown.shutdown().await.unwrap();
    _ = consensus_shutdown.shutdown().await.unwrap();

    info!("Client shutdown done.");

    _ = tokio::join!(client_handle, translator_handle);
    info!("Translator shutdown done.");
}

pub async fn run_tests(
    telos_client: &APIClient<DefaultProvider>,
    reth_provider: &TestProvider
) {
    let balance = reth_provider.get_balance(EOSIO_ADDR.clone()).await.unwrap();
    info!("Running live tests using address: {:?} with balance: {:?}", EOSIO_ADDR.to_string(), balance);

    let block = reth_provider.get_block(BlockId::latest(), BlockTransactionsKind::Full).await;
    info!("Latest block:\n {:?}", block);

    test_1k_txs(
        telos_client,
        reth_provider,
        Address::from_hex("0000000000000000deadbeef0000000000000000").unwrap()
    ).await;

    // set revision to 1
    let info = telos_client.v1_chain.get_info().await.unwrap();
    let eosio_key = PrivateKey::from_str(EOSIO_PKEY, false).unwrap();
    let unsigned_rev_tx = setrevision_tx(&info, 1);
    let rev_tx = sign_native_tx(&unsigned_rev_tx, &info, &eosio_key);
    telos_client.v1_chain.send_transaction(rev_tx).await.unwrap();

    test_blocknum_onchain(reth_provider).await;
}

pub async fn test_blocknum_onchain(reth_provider: &TestProvider) {
    sol! {
        #[sol(rpc, bytecode="6080604052348015600e575f80fd5b5060ef8061001b5f395ff3fe6080604052348015600e575f80fd5b50600436106030575f3560e01c80637f6c6f101460345780638fb82b0214604e575b5f80fd5b603a6056565b6040516045919060a2565b60405180910390f35b6054605d565b005b5f43905090565b437fc04eeb4cfe0799838abac8fa75bca975bff679179886c80c84a7b93229a1a61860405160405180910390a2565b5f819050919050565b609c81608c565b82525050565b5f60208201905060b35f8301846095565b9291505056fea264697066735822122003482ecf0ea4d820deb6b5ebd2755b67c3c8d4fb9ed50a8b4e0bce59613552df64736f6c634300081a0033")]
        contract BlockNumChecker {

            event BlockNumber(uint256 indexed number);

            function getBlockNum() public view returns (uint) {
                return block.number;
            }

            function logBlockNum() public {
                emit BlockNumber(block.number);
            }
        }
    }

    info!("Deploying contract using address {}", EOSIO_ADDR.to_string());

    let nonce = reth_provider.get_transaction_count(EOSIO_ADDR.clone()).await.unwrap();
    let chain_id = reth_provider.get_chain_id().await.unwrap();
    let gas_price = reth_provider.get_gas_price().await.unwrap();

    let legacy_tx = alloy_consensus::TxLegacy {
        chain_id: Some(chain_id),
        nonce,
        gas_price: gas_price.into(),
        gas_limit: 20_000_000,
        to: Create,
        value: U256::ZERO,
        input: BlockNumChecker::BYTECODE.to_vec().into(),
    };

    let legacy_tx_request = TransactionRequest {
        from: Some(EOSIO_ADDR.clone()),
        to: Some(legacy_tx.to),
        gas: Some(legacy_tx.gas_limit),
        gas_price: Some(legacy_tx.gas_price),
        value: Some(legacy_tx.value),
        input: TransactionInput::from(legacy_tx.input),
        nonce: Some(legacy_tx.nonce),
        chain_id: legacy_tx.chain_id,
        ..Default::default()
    };

    let deploy_result = reth_provider.send_transaction(legacy_tx_request.clone()).await.unwrap();

    let deploy_tx_hash = deploy_result.tx_hash();
    info!("Deployed contract with tx hash: {deploy_tx_hash}");
    let receipt = deploy_result.get_receipt().await.unwrap();
    info!("Receipt: {:?}", receipt);

    let contract_address = receipt.contract_address().unwrap();
    let block_num_checker = BlockNumChecker::new(contract_address, reth_provider.clone());

    let legacy_tx_request = TransactionRequest::default()
        .with_from(EOSIO_ADDR.clone())
        .with_to(contract_address)
        .with_gas_limit(20_000_000)
        .with_gas_price(gas_price)
        .with_input(block_num_checker.logBlockNum().calldata().clone())
        .with_nonce(reth_provider.get_transaction_count(EOSIO_ADDR.clone()).await.unwrap())
        .with_chain_id(chain_id);

    let log_block_num_tx_result = reth_provider.send_transaction(legacy_tx_request).await.unwrap();

    let log_block_num_tx_hash = log_block_num_tx_result.tx_hash();
    info!("Called contract with tx hash: {log_block_num_tx_hash}");
    let receipt = log_block_num_tx_result.get_receipt().await.unwrap();
    info!("log block number receipt: {:?}", receipt);
    let rpc_block_num = receipt.block_number().unwrap();
    let receipt = receipt.inner;
    let logs = receipt.logs();
    let first_log = logs[0].clone().inner;
    let block_num_event = BlockNumChecker::BlockNumber::decode_log(&first_log, true).unwrap();
    assert_eq!(U256::from(rpc_block_num), block_num_event.number);
    info!("Block numbers match inside transaction event");

    // test eip1559 transaction which is not supported
    test_1559_tx(reth_provider, EOSIO_ADDR.clone()).await;
    // test eip2930 transaction which is not supported
    test_2930_tx(reth_provider, EOSIO_ADDR.clone()).await;
    //  test double approve erc20 call
    test_double_approve_erc20(reth_provider, EOSIO_ADDR.clone()).await;
    // The below needs to be done using LegacyTransaction style call... with the current code it's including base_fee_per_gas and being rejected by reth
    // let block_num_latest = block_num_checker.getBlockNum().call().await.unwrap();
    // assert!(block_num_latest._0 > U256::from(rpc_block_num), "Latest block number via call to getBlockNum is not greater than the block number in the previous log event");
    //
    // let block_num_five_back = block_num_checker.getBlockNum().call().block(BlockId::number(rpc_block_num - 5)).await.unwrap();
    // assert!(block_num_five_back._0 == U256::from(rpc_block_num - 5), "Block number 5 blocks back via historical eth_call is not correct");

}

// test_1559_tx tests sending eip1559 transaction that has max_priority_fee_per_gas and max_fee_per_gas set
pub async fn test_1559_tx(provider: &TestProvider, sender_address: Address) {
    let nonce = provider.get_transaction_count(sender_address).await.unwrap();
    let chain_id = provider.get_chain_id().await.unwrap();
    let to_address: Address = Address::from_str("0x23CB6AE34A13a0977F4d7101eBc24B87Bb23F0d4").unwrap();

    let tx = TransactionRequest::default()
        .with_to(to_address)
        .with_nonce(nonce)
        .with_chain_id(chain_id)
        .with_value(U256::from(100))
        .with_gas_limit(21_000)
        .with_max_priority_fee_per_gas(1_000_000_000)
        .with_max_fee_per_gas(20_000_000_000);

    let tx_result = provider.send_transaction(tx).await;
    assert!(tx_result.is_err());
}

// test_2930_tx tests sending eip2930 transaction which has access_list provided
pub async fn test_2930_tx(provider: &TestProvider, sender_address: Address) {
    let nonce = provider.get_transaction_count(sender_address).await.unwrap();
    let chain_id = provider.get_chain_id().await.unwrap();
    let gas_price = provider.get_gas_price().await.unwrap();

    let to_address: Address = Address::from_str("0x23CB6AE34A13a0977F4d7101eBc24B87Bb23F0d4").unwrap();
    let tx = TransactionRequest::default()
        .to(to_address)
        .nonce(nonce)
        .value(U256::from(1e17))
        .with_chain_id(chain_id)
        .with_gas_price(gas_price)
        .with_gas_limit(20_000_000)
        .max_priority_fee_per_gas(1e11 as u128)
        .with_access_list(AccessList::from(vec![AccessListItem { address: to_address, storage_keys: vec![B256::ZERO] }]))
        .max_fee_per_gas(2e9 as u128);
    let tx_result = provider.send_transaction(tx).await;
    assert!(tx_result.is_err());
}


// test_double_approve_erc20 sends 2 transactions for approve on the ERC20 token and asserts that only once it is success
pub async fn test_double_approve_erc20(
    provider: &TestProvider,
    sender_address: Address,
) {
    let nonce = provider.get_transaction_count(sender_address).await.unwrap();
    let chain_id = provider.get_chain_id().await.unwrap();
    let gas_price = provider.get_gas_price().await.unwrap();

    let erc20_contract_address: Address =
        "0x49f54c5e2301eb9256438123e80762470c2c7ec2".parse().unwrap();
    let spender: Address = "0x23CB6AE34A13a0977F4d7101eBc24B87Bb23F0d4".parse().unwrap();
    let function_signature = "approve(address,uint256)";
    let amount: U256 = U256::from(0);
    let selector = &keccak256(function_signature.as_bytes())[..4];
    let amount_bytes: [u8; 32] = amount.to_be_bytes();
    let mut encoded_data = Vec::new();
    encoded_data.extend_from_slice(selector);
    encoded_data.extend_from_slice(spender.as_ref());
    encoded_data.extend_from_slice(&amount_bytes);
    let input_data = Bytes::from(encoded_data);

    // Build approve transaction
    let mut tx = TransactionRequest::default()
        .to(erc20_contract_address)
        .with_input(input_data)
        .nonce(nonce)
        .value(U256::from(10))
        .with_chain_id(chain_id)
        .with_gas_price(gas_price)
        .with_gas_limit(20_000_000);

    // call approve
    let tx_result = provider.send_transaction(tx.clone()).await;
    assert!(tx_result.is_ok());
    let receipt1 = tx_result.unwrap().get_receipt().await;
    assert!(receipt1.is_ok());

    let nonce = provider.get_transaction_count(sender_address).await.unwrap();
    tx.nonce = Some(nonce);

    // repeat approve
    let tx_result = provider.send_transaction(tx.clone()).await;
    assert!(tx_result.is_ok());

    let receipt2 = tx_result.unwrap().get_receipt().await;
    assert!(receipt2.is_ok());

    let block_number = receipt2.unwrap().block_number.unwrap();

    // make sure the block is included
    while let Some(block) = provider.get_block_by_number(Latest, false).await.unwrap() {
        if block.header.number == block_number {
            break;
        }
    }
}

pub async fn test_1k_txs(
    telos_client: &APIClient<DefaultProvider>,
    reth_provider: &TestProvider,
    target_addr: Address
) {
    let chain_id = reth_provider.get_chain_id().await.unwrap();
    let gas_price = reth_provider.get_gas_price().await.unwrap();

    let eosio_key = PrivateKey::from_str(EOSIO_PKEY, false).unwrap();

    let start_nonce = get_nonce(&telos_client, &EOSIO_ADDR).await;

    for _i in 0..2 {
        let info = telos_client.v1_chain.get_info().await.unwrap();
        let nonce = get_nonce(&telos_client, &EOSIO_ADDR).await;
        let tx = multi_raw_eth_tx(
            500,
            &info,
            name!("eosio"),
            PermissionLevel::new(name!("eosio"), name!("active")),
            false,
            None,
            &EOSIO_WALLET,
            chain_id,
            nonce,
            EOSIO_ADDR.clone(),
            target_addr,
            gas_price,
            20_000_000,
            U256::from(10)
        ).await;

        let signed_tx = sign_native_tx(&tx, &info, &eosio_key);

        let result = telos_client.v1_chain.send_transaction(signed_tx).await.unwrap();

        warn!("500 txs in block {}", result.processed.block_num);
        tokio::time::sleep(Duration::from_millis(750)).await;
    }

    tokio::time::sleep(Duration::from_millis(500)).await;
    let last_nonce = get_nonce(&telos_client, &EOSIO_ADDR).await;
    assert_eq!(last_nonce - start_nonce, 1000);
}