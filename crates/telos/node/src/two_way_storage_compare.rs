//! Two-way storage compare between Reth and Telos

use antelope::serializer::{Decoder, Encoder, Packer};
use antelope::chain::name::Name;
use std::collections::HashMap;
use alloy_primitives::{Address, B256, U256};
use antelope::api::client::{APIClient, DefaultProvider};
use antelope::api::v1::structs::{GetTableRowsParams, TableIndexType};
use antelope::{name, StructPacker};
use antelope::chain::checksum::{Checksum160, Checksum256};
use serde::{Deserialize, Serialize};
use tracing::{error, info};
use reth::primitives::{Account, BlockId};
use reth_db::common::KeyValue;
use reth::providers::StateProviderBox;
use reth_db::{PlainAccountState, PlainStorageState};

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

/// This struct holds matching statistics
#[derive(Debug, Clone, Default)]
pub struct MatchCounter {
    total_telos_accounts: u64,
    total_telos_storages: u64,
    mismatched_telos_accounts: u64,
    mismatched_telos_storages: u64,
    total_reth_accounts: u64,
    total_reth_storages: u64,
    mismatched_reth_accounts: u64,
    mismatched_reth_storages: u64,
}
impl MatchCounter {
    /// Creates a new match counter for two-way storage compare
    pub fn new() -> Self {
        Self {
            total_telos_accounts: 0,
            total_telos_storages: 0,
            mismatched_telos_accounts: 0,
            mismatched_telos_storages: 0,
            total_reth_accounts: 0,
            total_reth_storages: 0,
            mismatched_reth_accounts: 0,
            mismatched_reth_storages: 0,
        }
    }

    /// Prints the match counter
    pub fn print(&self) {
        info!("Comparing results:");
        info!("Total telos accounts: {}", self.total_telos_accounts);
        info!("Total telos storages: {}", self.total_telos_storages);
        info!("Mismatched telos accounts: {}", self.mismatched_telos_accounts);
        info!("Mismatched telos storages: {}", self.mismatched_telos_storages);
        info!("Total reth accounts: {}", self.total_reth_accounts);
        info!("Total reth storages: {}", self.total_reth_storages);
        info!("Mismatched reth accounts: {}", self.mismatched_reth_accounts);
        info!("Mismatched reth storages: {}", self.mismatched_reth_storages);
        info!("Matching result: {}",self.matches());
    }

    fn add_telos_total_account(&mut self) {
        self.total_telos_accounts += 1;
    }

    fn add_telos_total_storage(&mut self) {
        self.total_telos_storages += 1;
    }

    fn add_telos_mismatched_account(&mut self) {
        self.mismatched_telos_accounts += 1;
    }

    fn add_telos_mismatched_storage(&mut self) {
        self.mismatched_telos_storages += 1;
    }

    fn add_reth_total_account(&mut self) {
        self.total_reth_accounts += 1;
    }

    fn add_reth_total_storage(&mut self) {
        self.total_reth_storages += 1;
    }

    fn add_reth_mismatched_account(&mut self) {
        self.mismatched_reth_accounts += 1;
    }

    fn add_reth_mismatched_storage(&mut self) {
        self.mismatched_reth_storages += 1;
    }

    /// Check whether both sides matches
    pub fn matches(&self) -> bool {
        self.mismatched_telos_accounts == 0
            && self.mismatched_telos_storages == 0
            && self.mismatched_reth_accounts == 0
            && self.mismatched_reth_storages == 0
    }
}

/// This function compares reth and telos state against each other at specific height
pub async fn two_side_state_compare(
    account_table: HashMap<Address, Account>,
    accountstate_table: HashMap<(Address, B256), U256>,
    state_at_specific_height: StateProviderBox,
    plain_account_state: Vec<KeyValue<PlainAccountState>>,
    plain_storage_state: Vec<KeyValue<PlainStorageState>>,
) -> MatchCounter {

    let mut match_counter = MatchCounter::new();

    for (address, telos_account) in &account_table {
        let account_at_specific_height = state_at_specific_height.basic_account(*address);
        match account_at_specific_height {
            Ok(reth_account) => {
                match reth_account {
                    Some(reth_account) => {
                        if reth_account.balance != telos_account.balance || reth_account.nonce != telos_account.nonce {
                            match_counter.add_telos_mismatched_account();
                            error!("Difference in account: {:?}", address);
                            error!("Telos side: {:?}", telos_account);
                            error!("Reth side: {:?}", reth_account);
                        }
                    },
                    None => {
                        if telos_account.balance != U256::ZERO || telos_account.nonce != 0 {
                            match_counter.add_telos_mismatched_account();
                            error!("Difference in account: {:?}", address);
                            error!("Telos side: {:?}", telos_account);
                            error!("Reth side: None");
                        }
                    },
                }
            },
            Err(_) => {
                match_counter.add_telos_mismatched_account();
                error!("Difference in account: {:?}", address);
                error!("Telos side: {:?}", telos_account);
                error!("Reth side: None");
            },
        }
        match_counter.add_telos_total_account();
    }

    for ((address, key), telos_value) in &accountstate_table {
        let storage_at_specific_height = state_at_specific_height.storage(*address, *key);
        match storage_at_specific_height {
            Ok(storage) => {
                match storage {
                    Some(reth_value) => {
                        if reth_value != *telos_value {
                            match_counter.add_telos_mismatched_storage();
                            error!("Difference in accountstate: {:?}, key: {:?}", address, key);
                            error!("Telos side: {:?}", telos_value);
                            error!("Reth side: {:?}", reth_value);
                        }
                    },
                    None => {
                        match_counter.add_telos_mismatched_storage();
                        error!("Difference in accountstate: {:?}, key: {:?}", address, key);
                        error!("Telos side: {:?}", telos_value);
                        error!("Reth side: None");
                    },
                }
            },
            Err(_) => {
                match_counter.add_telos_mismatched_storage();
                error!("Difference in accountstate: {:?}, key: {:?}", address, key);
                error!("Telos side: {:?}", telos_value);
                error!("Reth side: None");
            },
        }
        match_counter.add_telos_total_storage();
    }


    for (address, _) in plain_account_state.iter() {
        let account_at_specific_height = state_at_specific_height.basic_account(*address);
        let telos_account = account_table.get(address);
        match account_at_specific_height {
            Ok(account) => {
                match account {
                    Some(reth_account) => {
                        if telos_account.is_none() {
                            match_counter.add_reth_mismatched_account();
                            error!("Difference in account: {:?}", address);
                            error!("Telos side: None");
                            error!("Reth side: {:?}", reth_account);
                        } else {
                            let telos_account_unwrapped = telos_account.unwrap();
                            if reth_account.balance != telos_account_unwrapped.balance || reth_account.nonce != telos_account_unwrapped.nonce {
                                match_counter.add_reth_mismatched_account();
                                error!("Difference in account: {:?}", address);
                                error!("Telos side: {:?}", telos_account);
                                error!("Reth side: {:?}", reth_account);
                            }
                        }

                    },
                    None => {
                        if telos_account.is_some() {
                            match_counter.add_reth_mismatched_account();
                            error!("Difference in account: {:?}", address);
                            error!("Telos side: {:?}", telos_account.unwrap());
                            error!("Reth side: None");
                        }
                    },
                }
            },
            Err(_) => {
                if telos_account.is_some() {
                    match_counter.add_reth_mismatched_account();
                    error!("Difference in account: {:?}", address);
                    error!("Telos side: {:?}", telos_account.unwrap());
                    error!("Reth side: None");
                }
            },
        }
        match_counter.add_reth_total_account();
    }

    for (address,storage_entry) in plain_storage_state.iter() {
        let storage_at_specific_height = state_at_specific_height.storage(*address, storage_entry.key);
        let telos_accountstate = accountstate_table.get(&(*address, storage_entry.key));
        match storage_at_specific_height {
            Ok(storage) => {
                match storage {
                    Some(reth_value) => {
                        if telos_accountstate.is_none() {
                            if reth_value != U256::ZERO {
                                match_counter.add_reth_mismatched_storage();
                                error!("Difference in accountstate: {:?}", address);
                                error!("Telos side: None");
                                error!("Reth side: {:?}", reth_value);
                            }
                        } else {
                            let telos_value = *telos_accountstate.unwrap();
                            if reth_value != telos_value {
                                match_counter.add_reth_mismatched_storage();
                                error!("Difference in accountstate: {:?}", address);
                                error!("Telos side: {:?}", telos_value);
                                error!("Reth side: {:?}", reth_value);
                            }
                        }
                    },
                    None => {
                        if telos_accountstate.is_some() {
                            match_counter.add_reth_mismatched_storage();
                            error!("Difference in accountstate: {:?}", address);
                            error!("Telos side: {:?}", telos_accountstate.unwrap());
                            error!("Reth side: None");
                        }
                    },
                }
            },
            Err(_) => {
                if telos_accountstate.is_some() {
                    match_counter.add_reth_mismatched_storage();
                    error!("Difference in accountstate: {:?}", address);
                    error!("Telos side: {:?}", telos_accountstate.unwrap());
                    error!("Reth side: None");
                }
            },
        }
        match_counter.add_reth_total_storage();
    }

    match_counter
}

/// This function retrieves account and accountstate tables from native RPC
pub async fn get_telos_tables(telos_rpc: &str, block_delta: u32) -> (HashMap<Address, Account>, HashMap<(Address, B256), U256>, BlockId) {

    let api_client = APIClient::<DefaultProvider>::default_provider(telos_rpc.into(), Some(5)).unwrap();
    let info_start = api_client.v1_chain.get_info().await.unwrap();

    let evm_block_num_start = info_start.head_block_num - block_delta;

    let mut has_more_account = true;
    let mut lower_bound_account = Some(TableIndexType::UINT64(0));

    let evm_block_id = BlockId::from(evm_block_num_start as u64);

    let mut account_table = HashMap::default();
    let mut accountstate_table = HashMap::default();

    while has_more_account {
        let query_params_account = GetTableRowsParams {
            code: name!("eosio.evm"),
            table: name!("account"),
            scope: None,
            lower_bound: lower_bound_account,
            upper_bound: None,
            limit: Some(5000),
            reverse: None,
            index_position: None,
            show_payer: None,
        };
        let account_rows = api_client.v1_chain.get_table_rows::<AccountRow>(query_params_account).await;
        if let Ok(account_rows) = account_rows {
            lower_bound_account = account_rows.next_key;
            has_more_account = lower_bound_account.is_some();
            for account_row in account_rows.rows {
                let address = Address::from_slice(account_row.address.data.as_slice());
                lower_bound_account = Some(TableIndexType::UINT64(account_row.index + 1));
                account_table.insert(address,Account {
                    nonce: account_row.nonce,
                    balance: U256::from_be_bytes(account_row.balance.data),
                    bytecode_hash: None,
                });
                let mut has_more_accountstate = true;
                let mut lower_bound_accountstate = Some(TableIndexType::UINT64(0));
                while has_more_accountstate {
                    let query_params_accountstate = GetTableRowsParams {
                        code: name!("eosio.evm"),
                        table: name!("accountstate"),
                        scope: Some(Name::from_u64(account_row.index)),
                        lower_bound: lower_bound_accountstate,
                        upper_bound: None,
                        limit: Some(5000),
                        reverse: None,
                        index_position: None,
                        show_payer: None,
                    };
                    let accountstate_rows = api_client.v1_chain.get_table_rows::<AccountStateRow>(query_params_accountstate).await;
                    if let Ok(accountstate_rows) = accountstate_rows {
                        lower_bound_accountstate = accountstate_rows.next_key;
                        has_more_accountstate = lower_bound_accountstate.is_some();
                        for accountstate_row in accountstate_rows.rows {
                            lower_bound_accountstate = Some(TableIndexType::UINT64(accountstate_row.index + 1));
                            accountstate_table.insert((address,B256::from(accountstate_row.key.data)),U256::from_be_bytes(accountstate_row.value.data));
                        }
                    } else {
                        panic!("Failed to fetch accountstate row");
                    }
                }
            }
        } else {
            panic!("Failed to fetch account row");
        }
    }

    let info_end = api_client.v1_chain.get_info().await.unwrap();
    let evm_block_num_end = info_end.head_block_num - block_delta;

    if evm_block_num_start != evm_block_num_end {
        panic!("Nodeos is syncing, it is impossible to get an accurate state from a syncing native RPC");
    }

    (account_table, accountstate_table, evm_block_id)
}