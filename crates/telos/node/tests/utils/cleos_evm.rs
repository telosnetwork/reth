use std::str::FromStr;
use alloy_network::{EthereumWallet, TransactionBuilder};
use alloy_primitives::{Address, U256};
use alloy_primitives::bytes::BytesMut;
use alloy_primitives::private::alloy_rlp::Encodable;
use antelope::api::v1::structs::{GetInfoResponse, GetTableRowsParams, IndexPosition, TableIndexType};
use antelope::chain::action::{Action, PermissionLevel};
use antelope::chain::checksum::{Checksum160, Checksum256};
use antelope::chain::name::Name;
use antelope::chain::transaction::{SignedTransaction, Transaction};
use antelope::chain::Packer;
use antelope::{name, StructPacker};
use antelope::serializer::{Decoder, Encoder};
use antelope::chain::private_key::PrivateKey;
use alloy_rpc_types::TransactionRequest;
use alloy_signer_local::PrivateKeySigner;
use antelope::api::client::{APIClient, DefaultProvider};
use lazy_static::lazy_static;
use reth_node_telos::two_way_storage_compare::AccountRow;

pub const EOSIO_PKEY: &str = "5Jr65kdYmn33C3UabzhmWDm2PuqbRfPuDStts3ZFNSBLM7TqaiL";
pub const EOSIO_EVM_PRIV_KEY: &str = "87ef69a835f8cd0c44ab99b7609a20b2ca7f1c8470af4f0e5b44db927d542084";
pub const EOSIO_EVM_PUB_KEY: &str = "c51fe232a0153f1f44572369cefe7b90f2ba08a5";

lazy_static! {
    pub static ref EOSIO_SIGNER: PrivateKeySigner = PrivateKeySigner::from_str(EOSIO_EVM_PRIV_KEY).unwrap();
    pub static ref EOSIO_ADDR: Address = Address::from_str(EOSIO_EVM_PUB_KEY).unwrap();
    pub static ref EOSIO_WALLET: EthereumWallet = EthereumWallet::from(EOSIO_SIGNER.clone());
}

pub fn pad_address(address: &Address) -> Checksum256 {
    let mut padded = vec![0; 12];
    padded.extend_from_slice(address.as_slice());
    Checksum256::from_bytes(padded.as_slice()).unwrap()
}

pub async fn get_account_by_addr(client: &APIClient<DefaultProvider>, address: &Address) -> AccountRow {
    let cs_addr = pad_address(address);
    let query_params_account = GetTableRowsParams {
        code: name!("eosio.evm"),
        table: name!("account"),
        scope: None,
        lower_bound: Some(TableIndexType::CHECKSUM256(cs_addr)),
        upper_bound: Some(TableIndexType::CHECKSUM256(cs_addr)),
        limit: Some(1),
        reverse: None,
        index_position: Some(IndexPosition::SECONDARY),
        show_payer: None,
    };
    let account_rows = client.v1_chain.get_table_rows::<AccountRow>(query_params_account)
        .await
        .expect(&format!("Network error trying find an account row for {}", cs_addr));

    account_rows.rows
        .first()
        .expect(&format!("Couldn\'t find an account row for {}", cs_addr))
        .clone()
}

pub async fn get_nonce(client: &APIClient<DefaultProvider>, address: &Address) -> u64 {
    let account = get_account_by_addr(client, address).await;
    account.nonce
}

#[allow(dead_code)]
pub fn setrevision_tx(
    info: &GetInfoResponse,
    new_revision: u32
) -> Transaction {
    #[derive(Clone, Eq, PartialEq, Default, StructPacker)]
    struct SetRevision {
        new_revision: u32,
    }

    let raw_data = SetRevision {
        new_revision
    };
    let rev_act = Action::new_ex(
        name!("eosio.evm"),
        name!("setrevision"),
        vec![PermissionLevel::new(name!("eosio.evm"), name!("active"))],
        raw_data,
    );

    Transaction {
        header: info.get_transaction_header(90),
        context_free_actions: vec![],
        actions: vec![rev_act],
        extension: vec![],
    }
}

#[allow(dead_code)]
pub async fn raw_eth_tx(
    info: &GetInfoResponse,
    ram_payer: Name,
    perms: PermissionLevel,
    estimate_gas: bool,
    sender: Option<Checksum160>,
    wallet: &EthereumWallet,
    chain_id: u64,
    nonce: u64,
    from: Address,
    to: Address,
    gas_price: u128,
    gas_limit: u64,
    value: U256
) -> Transaction {
    multi_raw_eth_tx(1, info, ram_payer, perms, estimate_gas, sender, wallet, chain_id, nonce, from, to, gas_price, gas_limit, value).await
}

#[allow(dead_code)]
pub async fn multi_raw_eth_tx(
    amount: usize,
    info: &GetInfoResponse,
    ram_payer: Name,
    perms: PermissionLevel,
    estimate_gas: bool,
    sender: Option<Checksum160>,
    wallet: &EthereumWallet,
    chain_id: u64,
    nonce: u64,
    from: Address,
    to: Address,
    gas_price: u128,
    gas_limit: u64,
    value: U256
) -> Transaction {
    let mut trx_header = info.get_transaction_header(90);
    trx_header.max_cpu_usage_ms = 200;
    let mut actions = vec![];
    for i in 0..amount {
        // generate raw evm tx
        let eth_tx_typed = TransactionRequest::default()
            .with_chain_id(chain_id)
            .with_nonce(nonce + i as u64)
            .with_from(from)
            .with_to(to)
            .with_gas_price(gas_price.into())
            .with_gas_limit(gas_limit)
            .with_value(value);

        let eth_tx_envelope = eth_tx_typed.build(&wallet).await.unwrap();
        let mut eth_tx_raw_buf = BytesMut::new();
        eth_tx_envelope.encode(&mut eth_tx_raw_buf);

        let eth_tx_raw: Vec<u8> = eth_tx_raw_buf.to_vec();

        // generate native transaction
        #[derive(Clone, Eq, PartialEq, Default, StructPacker)]
        struct Raw {
            ram_payer: Name,
            tx: Vec<u8>,
            estimate_gas: bool,
            sender: Option<Checksum160>,
        }

        let raw_data = Raw {
            ram_payer,
            tx: eth_tx_raw,
            estimate_gas,
            sender,
        };
        actions.push(Action::new_ex(
            name!("eosio.evm"),
            name!("raw"),
            vec![perms],
            raw_data,
        ));
    }

    Transaction {
        header: trx_header,
        context_free_actions: vec![],
        actions,
        extension: vec![],
    }
}


// #[allow(dead_code)]
// pub async fn doresources_sandwich(
//     info: &GetInfoResponse,
//     ram_payer: Name,
//     perms: PermissionLevel,
//     chain_id: u64
// ) -> Transaction {
//     let mut trx_header = info.get_transaction_header(90);
//     trx_header.max_cpu_usage_ms = 200;
//     let mut actions = vec![];
//     for i in 0..amount {
//         // generate raw evm tx
//         let eth_tx_typed = TransactionRequest::default()
//             .with_chain_id(chain_id)
//             .with_nonce(nonce + i as u64)
//             .with_from(from)
//             .with_to(to)
//             .with_gas_price(gas_price.into())
//             .with_gas_limit(gas_limit)
//             .with_value(value);
//
//         let eth_tx_envelope = eth_tx_typed.build(&wallet).await.unwrap();
//         let mut eth_tx_raw_buf = BytesMut::new();
//         eth_tx_envelope.encode(&mut eth_tx_raw_buf);
//
//         let eth_tx_raw: Vec<u8> = eth_tx_raw_buf.to_vec();
//
//         // generate native transaction
//         #[derive(Clone, Eq, PartialEq, Default, StructPacker)]
//         struct Raw {
//             ram_payer: Name,
//             tx: Vec<u8>,
//             estimate_gas: bool,
//             sender: Option<Checksum160>,
//         }
//
//         let raw_data = Raw {
//             ram_payer,
//             tx: eth_tx_raw,
//             estimate_gas,
//             sender,
//         };
//         actions.push(Action::new_ex(
//             name!("eosio.evm"),
//             name!("raw"),
//             vec![perms],
//             raw_data,
//         ));
//     }
//
//     Transaction {
//         header: trx_header,
//         context_free_actions: vec![],
//         actions,
//         extension: vec![],
//     }
// }

#[allow(dead_code)]
pub fn sign_native_tx(trx: &Transaction, info: &GetInfoResponse, private_key: &PrivateKey) -> SignedTransaction {
    let sign_data = trx.signing_data(info.chain_id.data.as_ref());
    SignedTransaction {
        transaction: trx.clone(),
        signatures: vec![private_key.sign_message(&sign_data)],
        context_free_data: vec![],
    }
}