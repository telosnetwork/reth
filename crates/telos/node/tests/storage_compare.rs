use std::str::FromStr;
use alloy_primitives::{Address, StorageValue, U256};
use alloy_provider::{Provider, ProviderBuilder, ReqwestProvider};
use alloy_rpc_types::BlockId;
use antelope::api::client::{APIClient, DefaultProvider};
use antelope::api::v1::structs::{GetTableRowsParams, TableIndexType};
use antelope::chain::name::Name;
use antelope::{name, StructPacker};
use antelope::chain::{Encoder, Decoder, Packer};
use antelope::chain::checksum::{Checksum160, Checksum256};
use reqwest::Url;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize, StructPacker)]
pub struct AccountRow {
    pub index: u64,
    pub address: Checksum160,
    pub account: Name,
    pub nonce: u64,
    pub code: Vec<u8>,
    pub balance: Checksum256,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, StructPacker)]
pub struct AccountStateRow {
    pub index: u64,
    pub key: Checksum256,
    pub value: Checksum256,
}

#[derive(Debug)]
struct MatchCounter {
    evm_block_number: BlockId,
    total_accounts: u64,
    total_storage_rows: u64,
    mismatched_accounts: u64,
    mismatched_storage_rows: u64,
}

impl MatchCounter {
    pub fn new(evm_block_number: BlockId) -> Self {
        Self {
            evm_block_number,
            total_accounts: 0,
            total_storage_rows: 0,
            mismatched_accounts: 0,
            mismatched_storage_rows: 0,
        }
    }

    pub fn print(&self) {
        println!("Compared at block: {:?}", self.evm_block_number);
        println!("Mismatched accounts: {}", self.mismatched_accounts);
        println!("Mismatched storage rows: {}", self.mismatched_storage_rows);
        println!("Matching accounts: {}", self.total_accounts - self.mismatched_accounts);
        println!("Matching storage rows: {}", self.total_storage_rows - self.mismatched_storage_rows);
        println!("Total accounts: {}", self.total_accounts);
        println!("Total storage rows: {}", self.total_storage_rows);
    }

    pub fn add_matching_account(&mut self) {
        self.total_accounts += 1;
    }

    pub fn add_matching_account_storage(&mut self) {
        self.total_storage_rows += 1;
    }

    pub fn add_mismatched_account(&mut self) {
        self.total_accounts += 1;
        self.mismatched_accounts += 1;
    }

    pub fn add_mismatched_account_storage(&mut self) {
        self.total_storage_rows += 1;
        self.mismatched_storage_rows += 1;
    }

    pub fn matches(&self) -> bool {
        self.mismatched_accounts == 0 && self.mismatched_storage_rows == 0
    }

}

#[tokio::test]
pub async fn compare() {
    // let evm_rpc = "http://38.91.106.49:9545";
    let evm_rpc = "http://localhost:8545";
    // let telos_rpc = "http://192.168.0.20:8884";
    let telos_rpc = "http://38.91.106.49:8899";
    let block_delta = 57;

    assert!(storage_matches(evm_rpc, telos_rpc, block_delta).await);
}

pub async fn storage_matches(evm_rpc: &str, telos_rpc: &str, block_delta: u32) -> bool {
    let api_client = APIClient::<DefaultProvider>::default_provider(telos_rpc.into(), Some(5)).unwrap();
    let info = api_client.v1_chain.get_info().await.unwrap();

    let provider = ProviderBuilder::new()
        .on_http(Url::from_str(evm_rpc).unwrap());

    let evm_block_num = info.head_block_num - block_delta;
    println!("Telos EVM Block Number: {:?}", evm_block_num);

    let mut has_more = true;
    let mut lower_bound = Some(TableIndexType::UINT64(0));

    let mut count = 0;

    let evm_block_id = BlockId::from(evm_block_num as u64);
    let mut match_counter = MatchCounter::new(evm_block_id);

    while has_more {
        let query_params = GetTableRowsParams {
            code: name!("eosio.evm"),
            table: name!("account"),
            scope: None,
            lower_bound,
            upper_bound: None,
            limit: Some(5000),
            reverse: None,
            index_position: None,
            show_payer: None,
        };
        let account_rows = api_client.v1_chain.get_table_rows::<AccountRow>(query_params).await;
        if let Ok(account_rows) = account_rows {
            lower_bound = account_rows.next_key;
            has_more = lower_bound.is_some();
            for account_row in account_rows.rows {
                let address = Address::from_slice(account_row.address.data.as_slice());
                lower_bound = Some(TableIndexType::UINT64(account_row.index + 1));
                compare_account(&mut match_counter, &account_row, &api_client, &provider).await;
                count += 1;
            }
        } else {
            panic!("Failed to fetch account row");
        }
    }

    match_counter.print();
    match_counter.matches()
}

async fn compare_account(match_counter: &mut MatchCounter, account_row: &AccountRow, api_client: &APIClient<DefaultProvider>, provider: &ReqwestProvider) {
    let at_block = match_counter.evm_block_number;
    let address = Address::from_slice(account_row.address.data.as_slice());
    let telos_balance = U256::from_be_slice(account_row.balance.data.as_slice());

    let reth_balance = provider.get_balance(address).block_id(at_block).await.unwrap();
    let reth_nonce = provider.get_transaction_count(address).block_id(at_block).await.unwrap();
    let reth_code = provider.get_code_at(address).block_id(at_block).await.unwrap().to_vec();

    let balance_missmatch = telos_balance != reth_balance;
    let nonce_missmatch = account_row.nonce != reth_nonce;
    let code_missmatch = account_row.code != reth_code;

    if balance_missmatch || nonce_missmatch || code_missmatch {
        println!("ACCOUNT MISMATCH!!!");
        println!("Account: {:?}", address);
        println!("Telos balance: {:?}", telos_balance);
        println!("Telos nonce: {:?}", account_row.nonce);
        println!("Telos code: {:?}", account_row.code);
        println!("Reth balance: {:?}", reth_balance);
        println!("Reth nonce: {:?}", reth_nonce);
        println!("Reth code: {:?}", reth_code);
        match_counter.add_mismatched_account();
    } else {
        match_counter.add_matching_account();
    }

    compare_account_storage(match_counter, account_row, api_client, provider).await;
}

async fn compare_account_storage(match_counter: &mut MatchCounter, account_row: &AccountRow, api_client: &APIClient<DefaultProvider>, provider: &ReqwestProvider) {
    let address = Address::from_slice(account_row.address.data.as_slice());

    let mut has_more = true;
    let mut lower_bound = Some(TableIndexType::UINT64(0));

    let mut count = 0;

    while has_more {
        let scope = if account_row.index == 0 {
            Some(name!(""))
        } else {
            Some(Name::from_u64(account_row.index))
        };
        let query_params = GetTableRowsParams {
            code: name!("eosio.evm"),
            table: name!("accountstate"),
            scope: Some(scope.unwrap()),
            lower_bound,
            upper_bound: None,
            limit: Some(5000),
            reverse: None,
            index_position: None,
            show_payer: None,
        };
        let account_state_rows = api_client.v1_chain.get_table_rows::<AccountStateRow>(query_params).await;
        if let Ok(account_state_rows) = account_state_rows {
            lower_bound = account_state_rows.next_key;
            has_more = lower_bound.is_some();
            for account_state_row in account_state_rows.rows {
                let key = U256::from_be_slice(account_state_row.key.data.as_slice());
                let telos_value: U256 = U256::from_be_slice(account_state_row.value.data.as_slice());
                let reth_value: U256 = provider.get_storage_at(address, key).block_id(match_counter.evm_block_number).await.unwrap();
                if telos_value != reth_value {
                    match_counter.add_mismatched_account_storage();
                    println!("STORAGE MISMATCH!!!");
                    println!("Storage account: {:?} with scope: {:?} and key: {:?}", address, scope.unwrap(), key);
                    println!("Telos Storage value: {:?}", telos_value);
                    println!("Reth storage value:  {:?}", reth_value);
                } else {
                    match_counter.add_matching_account_storage();
                }
                lower_bound = Some(TableIndexType::UINT64(account_state_row.index + 1));
                count += 1;
            }
        } else {
            panic!("Failed to fetch account state row");
        }
    }
}