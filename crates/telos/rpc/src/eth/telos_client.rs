use std::sync::Arc;
use reth_rpc_eth_types::error::EthResult;
use antelope::api::client::{APIClient, DefaultProvider};
use antelope::chain::name::Name;
use antelope::chain::private_key::PrivateKey;
use antelope::{chain::{Packer, Encoder, Decoder}, name, StructPacker};
use antelope::chain::action::{Action, PermissionLevel};
use antelope::chain::checksum::Checksum160;
use antelope::chain::transaction::{SignedTransaction, Transaction};
use backoff::Exponential;
use reth_rpc_eth_types::EthApiError;
use std::future::Future;
use tracing::{debug, error, warn};

/// A client to interact with a Telos node
#[derive(Debug, Clone)]
pub struct TelosClient {
    inner: Arc<TelosClientInner>,
}

#[derive(Debug, Clone)]
/// Telos arguments to construct a [`TelosClient`]
pub struct TelosClientArgs {
    /// Telos native endpoint to forward transactions to
    pub telos_endpoint: Option<String>,
    /// Signer account name
    pub signer_account: Option<String>,
    /// Signer permission name
    pub signer_permission: Option<String>,
    /// Signer private key
    pub signer_key: Option<String>,
}

#[derive(Debug, Clone)]
struct TelosClientInner {
    pub api_client: APIClient<DefaultProvider>,
    pub signer_account: Name,
    pub signer_permission: Name,
    pub signer_key: PrivateKey,
}

#[derive(StructPacker)]
struct RawActionData {
    pub ram_payer: Name,
    pub tx: Vec<u8>,
    pub estimate_gas: bool,
    pub sender: Option<Checksum160>,
}

mod backoff {
    use std::time::Duration;

    pub(crate) struct Exponential {
        current: u64,
        factor: u64,
        max: u64,
    }

    impl Iterator for Exponential {
        type Item = Duration;

        fn next(&mut self) -> Option<Self::Item> {
            let current = Duration::from_millis(self.current);
            self.current = (self.current * self.factor).min(self.max);
            Some(current)
        }
    }

    impl Default for Exponential {
        fn default() -> Self {
            Self { current: 2, factor: 2, max: 4096 } // 8 seconds total
        }
    }
}

async fn retry<F, Fut, T>(mut call: F) -> Result<T, String>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, String>>,
{
    const RETRIES: usize = 12;
    let mut backoff = Exponential::default().take(RETRIES - 1);
    let mut retry_num = 0;
    loop {
        match (call().await, backoff.next()) {
            (Ok(value), _) => return Ok(value),
            (Err(_), Some(wait)) => tokio::time::sleep(wait).await,
            (Err(error), None) => return Err(error),
        }
        retry_num += 1;
        debug!("Retrying, attempt number: {retry_num}");
    }
}

impl TelosClient {
    /// Creates a new [`TelosClient`].
    pub fn new(telos_client_args: TelosClientArgs) -> Self {
        if telos_client_args.telos_endpoint.is_none()
            || telos_client_args.signer_account.is_none()
            || telos_client_args.signer_permission.is_none()
            || telos_client_args.signer_key.is_none()
        {
            panic!("Should not construct TelosClient without proper TelosArgs with telos_endpoint and signer args");
        }
        let api_client = APIClient::<DefaultProvider>::default_provider(telos_client_args.telos_endpoint.unwrap().into(), Some(3)).unwrap();
        let inner = TelosClientInner {
            api_client,
            signer_account: name!(&telos_client_args.signer_account.unwrap()),
            signer_permission: name!(&telos_client_args.signer_permission.unwrap()),
            signer_key: PrivateKey::from_str(&telos_client_args.signer_key.unwrap(), false)
                .unwrap(),
        };
        Self { inner: Arc::new(inner) }
    }

    /// Sends a raw transaction to Telos native network for inclusion in a block
    pub async fn send_to_telos(&self, tx: &[u8]) -> EthResult<()> {
        let get_info = self.inner.api_client.v1_chain.get_info().await.unwrap();
        let trx_header = get_info.get_transaction_header(90);
        let trx_header = trx_header.clone();
        let trx_bytes = tx.to_vec();

        let raw_action_data = RawActionData {
            ram_payer: name!("eosio.evm"),
            tx: trx_bytes,
            estimate_gas: false,
            sender: None,
        };

        let action = Action::new_ex(
            name!("eosio.evm"),
            name!("raw"),
            vec![PermissionLevel::new(self.inner.signer_account, self.inner.signer_permission)],
            raw_action_data,
        );

        let transaction = Transaction {
            header: trx_header,
            context_free_actions: vec![],
            actions: vec![action],
            extension: vec![],
        };

        let signed_telos_transaction = SignedTransaction {
            transaction: transaction.clone(),
            signatures: vec![self
                .inner
                .signer_key
                .sign_message(&transaction.signing_data(get_info.chain_id.data.as_ref()))],
            context_free_data: vec![],
        };

        let tx_response = retry(|| async {
            self.inner
                .api_client
                .v1_chain
                .send_transaction(signed_telos_transaction.clone())
                .await
                .map_err(|error| {
                    warn!("{error:?}");
                    format!("{error:?}")
                })
        })
        .await;

        let tx = match tx_response {
            Ok(value) => value,
            Err(err) => {
                error!("Error sending transaction to Telos: {:?}", err);
                return Err(EthApiError::EvmCustom(
                    "Error sending transaction to Telos".to_string(),
                ));
            }
        };

        debug!("Transaction sent to Telos: {:?}", tx.transaction_id);
        Ok(())
    }
}
