use reth_chainspec::EthereumHardforks;
use reth_evm::ConfigureEvm;
use reth_node_api::{FullNodeComponents, NodeTypes};
use reth_primitives::Header;
use reth_rpc_eth_api::helpers::{Call, EthCall, LoadState, SpawnBlocking};

use crate::eth::TelosEthApi;
use crate::error::TelosEthApiError;


impl<N> EthCall for TelosEthApi<N>
where
    Self: Call,
    N: FullNodeComponents<Types: NodeTypes<ChainSpec: EthereumHardforks>>,
{
}

impl<N> Call for TelosEthApi<N>
where
    Self: LoadState + SpawnBlocking,
    Self::Error: From<TelosEthApiError>,
    N: FullNodeComponents,
{
    #[inline]
    fn call_gas_limit(&self) -> u64 {
        self.inner.gas_cap()
    }

    #[inline]
    fn max_simulate_blocks(&self) -> u64 {
        self.inner.max_simulate_blocks()
    }

    #[inline]
    fn evm_config(&self) -> &impl ConfigureEvm<Header = Header> {
        self.inner.evm_config()
    }

}
