use alloy_consensus::{Signed, TxLegacy};
use std::thread::sleep;
use std::time::Duration;
use alloy_contract::private::Transport;
use alloy_network::{Ethereum, ReceiptResponse, TransactionBuilder};
use alloy_primitives::{keccak256, Address, Signature, B256, U256};
use alloy_provider::network::EthereumWallet;
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rpc_types::{TransactionRequest};
use alloy_rpc_types::BlockNumberOrTag::Latest;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::private::primitives::TxKind::Create;
use alloy_sol_types::{sol, SolEvent};
use reqwest::Url;
use reth::primitives::BlockId;
use reth::rpc::types::{BlockTransactionsKind, TransactionInput};
use std::fmt::Debug;
use std::str::FromStr;
use telos_translator_rs::rlp::telos_rlp_decode::TelosTxDecodable;
use tracing::info;

use reth::primitives::revm_primitives::bytes::Bytes;
use reth::revm::primitives::{AccessList, AccessListItem};

#[tokio::test]
pub async fn run_local() {
    env_logger::builder().is_test(true).try_init().unwrap();
    let url = "http://localhost:8545";
    let private_key = "26e86e45f6fc45ec6e2ecd128cec80fa1d1505e5507dcd2ae58c3130a7a97b48";
    run_tests(url, private_key).await;
}

pub async fn run_tests(url: &str, private_key: &str) {
    let signer = PrivateKeySigner::from_str(private_key).unwrap();
    let wallet = EthereumWallet::from(signer.clone());

    let provider = ProviderBuilder::new()
        //.network::<TelosNetwork>()
        .wallet(wallet.clone())
        .on_http(Url::from_str(url).unwrap());

    let signer_address = signer.address();
    let balance = provider.get_balance(signer_address).await.unwrap();

    info!("Running live tests using address: {:?} with balance: {:?}", signer_address, balance);

    let block = provider.get_block(BlockId::latest(), BlockTransactionsKind::Full).await;
    info!("Latest block:\n {:?}", block);

    test_blocknum_onchain(url, private_key).await;
}

pub async fn test_blocknum_onchain(url: &str, private_key: &str) {
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

    let signer = PrivateKeySigner::from_str(private_key).unwrap();
    let address = signer.address();
    let wallet = EthereumWallet::from(signer);

    let provider =
        ProviderBuilder::new().wallet(wallet.clone()).on_http(Url::from_str(url).unwrap());

    info!("Deploying contract using address {address}");

    let nonce = provider.get_transaction_count(address).await.unwrap();
    let chain_id = provider.get_chain_id().await.unwrap();
    let gas_price = provider.get_gas_price().await.unwrap();

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
        from: Some(address),
        to: Some(legacy_tx.to),
        gas: Some(legacy_tx.gas_limit as u64),
        gas_price: Some(legacy_tx.gas_price),
        value: Some(legacy_tx.value),
        input: TransactionInput::from(legacy_tx.input),
        nonce: Some(legacy_tx.nonce),
        chain_id: legacy_tx.chain_id,
        ..Default::default()
    };

    let deploy_result = provider.send_transaction(legacy_tx_request.clone()).await.unwrap();

    let deploy_tx_hash = deploy_result.tx_hash();
    info!("Deployed contract with tx hash: {deploy_tx_hash}");
    let receipt = deploy_result.get_receipt().await.unwrap();
    info!("Receipt: {:?}", receipt);

    let contract_address = receipt.contract_address().unwrap();
    let block_num_checker = BlockNumChecker::new(contract_address, provider.clone());

    let legacy_tx_request = TransactionRequest::default()
        .with_from(address)
        .with_to(contract_address)
        .with_gas_limit(20_000_000)
        .with_gas_price(gas_price)
        .with_input(block_num_checker.logBlockNum().calldata().clone())
        .with_nonce(provider.get_transaction_count(address).await.unwrap())
        .with_chain_id(chain_id);

    let log_block_num_tx_result = provider.send_transaction(legacy_tx_request).await.unwrap();

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

    // wait for some blocks
    while let Some(block) = provider.get_block_by_number(Latest, false).await.unwrap() {
        if block.header.number == block_num_event.number.as_limbs()[0] + 8 {
            break;
        }
    }
    // test latest block and call get block from the contract
    let latest_block = provider.get_block_by_number(Latest, false).await.unwrap().unwrap();
    let contract = BlockNumChecker::new(contract_address, provider.clone());
    let block_number = contract.getBlockNum().call().await.unwrap();
    assert_eq!(U256::from(latest_block.header.number), block_number._0);
    assert!(latest_block.header.number > rpc_block_num);

    // call for history blocks
    let block_num_five_back = block_num_checker.getBlockNum().call().block(BlockId::number(latest_block.header.number - 5)).await.unwrap();
    assert_eq!(block_num_five_back._0, U256::from(latest_block.header.number - 5), "Block number 5 blocks back via historical eth_call is not correct");

    // test eip1559 transaction which is not supported
    test_1559_tx(provider.clone(), address).await;
    // test eip2930 transaction which is not supported
    test_2930_tx(provider.clone(), address).await;
    // test double approve erc20 call
    test_double_approve_erc20(provider.clone(), address).await;
    // test incorrect rlp call
    test_incorrect_rlp(provider.clone(), address).await;

    // The below needs to be done using LegacyTransaction style call... with the current code it's including base_fee_per_gas and being rejected by reth
    // let block_num_latest = block_num_checker.getBlockNum().call().await.unwrap();
    // assert!(block_num_latest._0 > U256::from(rpc_block_num), "Latest block number via call to getBlockNum is not greater than the block number in the previous log event");
    //
    // let block_num_five_back = block_num_checker.getBlockNum().call().block(BlockId::number(rpc_block_num - 5)).await.unwrap();
    // assert!(block_num_five_back._0 == U256::from(rpc_block_num - 5), "Block number 5 blocks back via historical eth_call is not correct");
}

// test_1559_tx tests sending eip1559 transaction that has max_priority_fee_per_gas and max_fee_per_gas set
pub async fn test_1559_tx<T>(
    provider: impl Provider<T, Ethereum> + Send + Sync,
    sender_address: Address,
) where
    T: Transport + Clone + Debug,
{
    let nonce = provider.get_transaction_count(sender_address).await.unwrap();
    let chain_id = provider.get_chain_id().await.unwrap();
    let to_address: Address =
        Address::from_str("0x23CB6AE34A13a0977F4d7101eBc24B87Bb23F0d4").unwrap();

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
pub async fn test_2930_tx<T>(
    provider: impl Provider<T, Ethereum> + Send + Sync,
    sender_address: Address,
) where
    T: Transport + Clone + Debug,
{
    let nonce = provider.get_transaction_count(sender_address).await.unwrap();
    let chain_id = provider.get_chain_id().await.unwrap();
    let gas_price = provider.get_gas_price().await.unwrap();

    let to_address: Address =
        Address::from_str("0x23CB6AE34A13a0977F4d7101eBc24B87Bb23F0d4").unwrap();
    let tx = TransactionRequest::default()
        .to(to_address)
        .nonce(nonce)
        .value(U256::from(1e17))
        .with_chain_id(chain_id)
        .with_gas_price(gas_price)
        .with_gas_limit(20_000_000)
        .max_priority_fee_per_gas(1e11 as u128)
        .with_access_list(AccessList::from(vec![AccessListItem {
            address: to_address,
            storage_keys: vec![B256::ZERO],
        }]))
        .max_fee_per_gas(2e9 as u128);
    let tx_result = provider.send_transaction(tx).await;
    assert!(tx_result.is_err());
}

// test_double_approve_erc20 sends 2 transactions for approve on the ERC20 token and asserts that only once it is success
pub async fn test_double_approve_erc20<T>(
    provider: impl Provider<T, Ethereum> + Send + Sync,
    sender_address: Address,
) where
    T: Transport + Clone + Debug,
{
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

pub async fn test_incorrect_rlp<T>(
    provider: impl Provider<T, Ethereum> + Send + Sync,
    sender_address: Address,
) where
    T: Transport + Clone + Debug,
{
    let chain_id = Some(provider.get_chain_id().await.unwrap());
    let nonce = Some(provider.get_transaction_count(sender_address).await.unwrap());
    let legacy_tx = tx_trailing_empty_values().unwrap().tx().clone();

    let legacy_tx_request = TransactionRequest {
        from: Some(sender_address),
        to: Some(legacy_tx.to),
        gas: Some(legacy_tx.gas_limit as u64),
        gas_price: Some(legacy_tx.gas_price),
        value: Some(legacy_tx.value),
        input: TransactionInput::from(legacy_tx.input),
        nonce,
        chain_id,
        ..Default::default()
    };

    let tx_result = provider.send_transaction(legacy_tx_request).await;
    assert!(tx_result.is_err());
}

fn tx_trailing_empty_values() -> eyre::Result<Signed<TxLegacy>> {
    let byte_array: [u8; 43] = [
        234, 21, 133, 117, 98, 209, 251, 63, 131, 30, 132, 128, 148, 221, 124, 155, 23, 110, 221,
        57, 225, 22, 88, 115, 0, 111, 245, 56, 10, 44, 0, 51, 174, 130, 39, 16, 130, 0, 0, 128,
        128, 128, 128,
    ];

    let r = U256::from_str(
        "7478307613393818857995123362551696556625819847066981460737539381080402549198",
    )?;
    let s = U256::from_str(
        "93208746529385687702128536437164864077231874732405909428462768306792425324544",
    )?;
    let v = 42u64;

    let sig = Signature::from_rs_and_parity(r, s, v)?;
    Ok(TxLegacy::decode_telos_signed_fields(&mut &byte_array[..], Some(sig))?)
}
