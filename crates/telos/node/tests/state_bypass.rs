use std::{fmt, fs};
use std::fmt::{Display, Formatter};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use alloy_provider::{Provider, ProviderBuilder};
use reqwest::Url;
use serde_json::json;
use telos_consensus_client::execution_api_client::{ExecutionApiClient, RpcRequest};
use telos_consensus_client::execution_api_client::ExecutionApiMethod::{ForkChoiceUpdatedV1, NewPayloadV1};
use tracing::info;
use reth::args::RpcServerArgs;
use reth::builder::NodeConfig;
use alloy_primitives::{Address, B256, hex, U256, Bytes, map::HashMap};
use alloy_primitives::hex::FromHex;
use alloy_rpc_types::engine::ExecutionPayloadV1;
use reth::primitives::revm_primitives::{Bytecode as RevmBytecode, LegacyAnalyzedBytecode};
use reth::providers::ProviderError;
use reth::revm;
use reth::revm::db::{CacheDB, EmptyDBTyped, StorageWithOriginalValues, states::StorageSlot};
use reth::revm::{Database, DatabaseCommit, DatabaseRef, Evm, State, TransitionAccount};
use reth::revm::primitives::{AccountInfo, EvmStorageSlot};
use reth::rpc::types::engine::ForkchoiceState;
use reth::tasks::TaskManager;
use reth_chainspec::{ChainSpec, ChainSpecBuilder, TEVMTESTNET};
use reth_e2e_test_utils::node::NodeTestContext;
use reth_node_builder::NodeBuilder;
use reth_node_telos::{TelosArgs, TelosNode};
use reth_primitives::constants::{EMPTY_ROOT_HASH, MIN_PROTOCOL_BASE_FEE};
use reth_primitives::revm_primitives::AccountStatus;
use reth_telos_rpc::TelosClient;
use reth_telos_rpc_engine_api::compare::compare_state_diffs;
use reth_telos_rpc_engine_api::structs::{TelosAccountTableRow, TelosAccountStateTableRow, TelosEngineAPIExtraFields};
use revm::primitives::Account;

#[derive(Debug)]
enum MockDBError {
    GenericError(String)
}

impl Into<ProviderError> for MockDBError {
    fn into(self) -> ProviderError {
        match self {
            MockDBError::GenericError(msg) => {
                ProviderError::NippyJar(msg)
            }
        }
    }
}

impl Display for MockDBError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            MockDBError::GenericError(msg) => {
                f.write_str(&msg)
            }
        }
    }
}

fn init_reth() -> eyre::Result<(NodeConfig<ChainSpec>, String)> {
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

#[tokio::test]
async fn test_integration_tevm_only() {
    tracing_subscriber::fmt::init();

    let (node_config, jwt_secret) = init_reth().unwrap();

    let exec = TaskManager::current();
    let exec = exec.executor();

    reth_tracing::init_test_tracing();

    let telos_args = TelosArgs {
        telos_endpoint: None,
        signer_account: Some("rpc.evm".to_string()),
        signer_permission: Some("active".to_string()),
        signer_key: Some("5Jr65kdYmn33C3UabzhmWDm2PuqbRfPuDStts3ZFNSBLM7TqaiL".to_string()),
        gas_cache_seconds: None,
        experimental: false,
        persistence_threshold: 0,
        memory_block_buffer_target: 0,
        max_execute_block_batch_size: 0,
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
    println!("Starting Reth on RPC port {}!", rpc_port);
    let _ = NodeTestContext::new(node_handle.node.clone()).await.unwrap();

    let custom_balance = U256::from(80085);

    let exec_client = ExecutionApiClient::new(&format!("http://127.0.0.1:{}", execution_port), &jwt_secret).unwrap();

    let execution_payload = ExecutionPayloadV1 {
        parent_hash: B256::from_hex("b25034033c9ca7a40e879ddcc29cf69071a22df06688b5fe8cc2d68b4e0528f9").unwrap(),
        fee_recipient: Default::default(),
        state_root: EMPTY_ROOT_HASH,
        receipts_root: EMPTY_ROOT_HASH,
        logs_bloom: Default::default(),
        prev_randao: Default::default(),
        block_number: 1,
        gas_limit: 0x7fffffff,
        gas_used: 0,
        timestamp: 1728067687,
        extra_data: Default::default(),
        base_fee_per_gas: U256::try_from(MIN_PROTOCOL_BASE_FEE).unwrap(),
        block_hash: B256::from_hex("0a1d73423169c8b4124121d40c0e13eb078621e73effd2d183f9a1d8017537dd").unwrap(),
        transactions: vec![],
    };

    let test_addr = Address::from_hex("00000000000000000000000000000000deadbeef").unwrap();

    let extra_fields = TelosEngineAPIExtraFields {
        statediffs_account: Some(vec![TelosAccountTableRow {
            removed: false,
            address: test_addr,
            account: "eosio".to_string(),
            nonce: 0,
            code: Default::default(),
            balance: custom_balance,
        }]),
        statediffs_accountstate: Some(vec![]),
        revision_changes: None,
        gasprice_changes: None,
        new_addresses_using_create: Some(vec![]),
        new_addresses_using_openwallet: Some(vec![]),
        receipts: Some(vec![]),
    };

    let block_req = RpcRequest {
        method: NewPayloadV1,
        params: vec![
            json![execution_payload],
            json![extra_fields]
        ].into()
    };

    let new_block_result = exec_client.rpc(block_req).await.unwrap();

    info!("new_block: {:#?}", new_block_result);

    let fork_choice_result = exec_client.rpc(RpcRequest {
        method: ForkChoiceUpdatedV1,
        params: json![vec![ForkchoiceState {
            head_block_hash: execution_payload.block_hash,
            safe_block_hash: execution_payload.block_hash,
            finalized_block_hash: execution_payload.block_hash
        }]]
    }).await.unwrap();

    info!("fork_choice: {:#?}", fork_choice_result);


    let provider = ProviderBuilder::new()
        //.network::<TelosNetwork>()
        .on_http(Url::from_str(format!("http://localhost:{}", rpc_port).as_str()).unwrap());

    let balance = provider.get_balance(test_addr).await.unwrap();
    info!("balance: {:#?}", balance);

    assert_eq!(balance, custom_balance);
}

#[test]
fn test_db_both_sides_present_but_dif() {
    let test_addr = Address::from_str("00000000000000000000000000000000deadbeef").unwrap();

    let init_balance = U256::from(0);
    let custom_balance = U256::from(80085);

    let init_nonce = 0;
    let custom_nonce = 69;

    let revm_acc_info = AccountInfo {
        balance: init_balance,
        nonce: init_nonce,
        code_hash: Default::default(),
        code: None,
    };

    let mut db = CacheDB::new(EmptyDBTyped::<MockDBError>::new());
    db.insert_account_info(test_addr, revm_acc_info);

    let mut state = State::builder().with_database(db).build();

    let mut evm = Evm::builder().with_db(&mut state).build();

    let statediffs_account = vec![TelosAccountTableRow {
        removed: false,
        address: test_addr,
        account: "eosio".to_string(),
        nonce: custom_nonce,
        code: Default::default(),
        balance: custom_balance,
    }];

    compare_state_diffs(
        &mut evm,
        HashMap::default(),
        statediffs_account.clone(),
        vec![],
        vec![],
        vec![],
       false
    );

    let db_acc = evm.db_mut().basic(test_addr).unwrap().unwrap();
    assert_eq!(db_acc.nonce, statediffs_account[0].nonce);
    assert_eq!(db_acc.balance, statediffs_account[0].balance);
}

#[test]
fn test_db_both_sides_only_code() {
    let test_addr = Address::from_str("00000000000000000000000000000000deadbeef").unwrap();

    let custom_code = Bytes::from(&hex!("ffff"));
    let custom_bytecode = RevmBytecode::LegacyRaw(custom_code.clone());

    let revm_acc_info = AccountInfo {
        balance: U256::from(0),
        nonce: 0,
        code_hash: Default::default(),
        code: None,
    };

    let mut db = CacheDB::new(EmptyDBTyped::<MockDBError>::new());
    db.insert_account_info(test_addr, revm_acc_info);

    let mut state = State::builder().with_database(db).build();

    let mut evm = Evm::builder().with_db(&mut state).build();

    let statediffs_account = vec![TelosAccountTableRow {
        removed: false,
        address: test_addr,
        account: "eosio".to_string(),
        nonce: 0,
        code: custom_code.clone(),
        balance: U256::from(0),
    }];

    compare_state_diffs(
        &mut evm,
        HashMap::default(),
        statediffs_account.clone(),
        vec![],
        vec![],
        vec![],
        false
    );

    let db_acc = evm.db_mut().basic(test_addr).unwrap().unwrap();
    assert_eq!(db_acc.code, Some(custom_bytecode));
}

#[test]
fn test_revm_state_both_sides_present_but_dif() {
    let test_addr = Address::from_str("00000000000000000000000000000000deadbeef").unwrap();

    let revm_acc_info = AccountInfo {
        balance: U256::from(1),
        nonce: 0,
        code_hash: Default::default(),
        code: None,
    };

    let mut revm_state_diffs = HashMap::default();

    let mut transition_account = TransitionAccount::new_empty_eip161(HashMap::default());

    transition_account.info = Some(revm_acc_info);

    revm_state_diffs.insert(test_addr, transition_account);

    let mut db = CacheDB::new(EmptyDBTyped::<MockDBError>::new());

    let mut state = State::builder().with_database(db).build();

    let mut evm = Evm::builder().with_db(&mut state).build();

    let statediffs_account = vec![TelosAccountTableRow {
        removed: false,
        address: test_addr,
        account: "eosio".to_string(),
        nonce: 1,
        code: Default::default(),
        balance: U256::from(80085),
    }];

    compare_state_diffs(
        &mut evm,
        revm_state_diffs,
        statediffs_account.clone(),
        vec![],
        vec![],
        vec![],
        false
    );

    let db_acc = evm.db_mut().basic(test_addr).unwrap().unwrap();
    assert_eq!(db_acc.nonce, statediffs_account[0].nonce);
    assert_eq!(db_acc.balance, statediffs_account[0].balance);
}

#[test]
fn test_tevm_only() {
    let test_addr = Address::from_str("00000000000000000000000000000000deadbeef").unwrap();

    let mut db = CacheDB::new(EmptyDBTyped::<MockDBError>::new());

    let mut state = State::builder().with_database(db).build();

    let mut evm = Evm::builder().with_db(&mut state).build();

    let statediffs_account = vec![TelosAccountTableRow {
        removed: false,
        address: test_addr,
        account: "eosio".to_string(),
        nonce: 1,
        code: Default::default(),
        balance: U256::from(80085),
    }];

    compare_state_diffs(
        &mut evm,
        HashMap::default(),
        statediffs_account.clone(),
        vec![],
        vec![],
        vec![],
        false
    );

    let db_acc = evm.db_mut().basic(test_addr).unwrap().unwrap();
    assert_eq!(db_acc.nonce, statediffs_account[0].nonce);
    assert_eq!(db_acc.balance, statediffs_account[0].balance);
}

#[test]
fn test_accstate_diff_from_storage() {
    let test_addr = Address::from_str("00000000000000000000000000000000deadbeef").unwrap();

    let revm_acc_info = AccountInfo {
        balance: U256::from(1),
        nonce: 0,
        code_hash: Default::default(),
        code: None,
    };

    let key = U256::from(420);
    let value = U256::from(0);
    let custom_value = U256::from(80085);

    let mut db = CacheDB::new(EmptyDBTyped::<MockDBError>::new());

    let mut storage = HashMap::default();
    storage.insert(key, value);

    let mut state = State::builder().with_database(db).build();

    state.insert_account_with_storage(test_addr, revm_acc_info, storage);

    let mut evm = Evm::builder().with_db(&mut state).build();

    let statediffs_accountstate = vec![TelosAccountStateTableRow {
        removed: false,
        address: test_addr,
        key,
        value: custom_value
    }];

    compare_state_diffs(
        &mut evm,
        HashMap::default(),
        vec![],
        statediffs_accountstate.clone(),
        vec![],
        vec![],
        false
    );

    let db_value = evm.db_mut().storage(test_addr, key).unwrap();
    assert_eq!(db_value, custom_value);
}
// #[test]
// fn test_accstate_telos_only() {
//     let test_addr = Address::from_str("00000000000000000000000000000000deadbeef").unwrap();
//
//     let key = U256::from(420);
//     let custom_value = U256::from(80085);
//
//     let mut db = CacheDB::new(EmptyDBTyped::<MockDBError>::new());
//
//     let mut state = State::builder().with_database(db).build();
//
//     // state.insert_not_existing(test_addr);
//
//     let mut evm = Evm::builder().with_db(&mut state).build();
//
//     let statediffs_accountstate = vec![TelosAccountStateTableRow {
//         removed: false,
//         address: test_addr,
//         key,
//         value: custom_value
//     }];
//
//     compare_state_diffs(
//         &mut evm,
//         HashMap::default(),
//         vec![],
//         statediffs_accountstate.clone(),
//         vec![],
//         vec![],
//         true
//     );
// }
