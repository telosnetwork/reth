//! Telos node implementation

use reth_chainspec::{ChainSpec};
use crate::args::TelosArgs;
use reth_ethereum_engine_primitives::{
    EthBuiltPayload, EthEngineTypes, EthPayloadAttributes, EthPayloadBuilderAttributes,
};
use reth_node_api::{FullNodeComponents, FullNodeTypes, NodeAddOns, NodeTypes};
use reth_node_builder::components::ComponentsBuilder;
use reth_node_builder::{Node, PayloadTypes};
use reth_node_ethereum::node::{EthereumConsensusBuilder, EthereumEngineValidatorBuilder, EthereumExecutorBuilder, EthereumNetworkBuilder, EthereumPayloadBuilder, EthereumPoolBuilder};
use reth_node_types::NodeTypesWithEngine;
use reth_telos_rpc::eth::TelosEthApi;

/// Type configuration for a regular Telos node.
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct TelosNode {
    /// Additional Telos args
    pub args: TelosArgs,
}

impl TelosNode {
    /// Creates a new instance of the Telos node type.
    pub const fn new(args: TelosArgs) -> Self {
        Self { args }
    }

    /// Returns a [`ComponentsBuilder`] configured for a regular Ethereum node.
    pub fn components<Node>() -> ComponentsBuilder<
        Node,
        EthereumPoolBuilder,
        EthereumPayloadBuilder,
        EthereumNetworkBuilder,
        EthereumExecutorBuilder,
        EthereumConsensusBuilder,
        EthereumEngineValidatorBuilder,
    >
    where
        Node: FullNodeTypes<Types: NodeTypes<ChainSpec = ChainSpec>>,
        <Node::Types as NodeTypesWithEngine>::Engine: PayloadTypes<
            BuiltPayload = EthBuiltPayload,
            PayloadAttributes = EthPayloadAttributes,
            PayloadBuilderAttributes = EthPayloadBuilderAttributes,
        >,
    {
        ComponentsBuilder::default()
            .node_types::<Node>()
            .pool(EthereumPoolBuilder::default())
            .payload(EthereumPayloadBuilder::default())
            .network(EthereumNetworkBuilder::default())
            .executor(EthereumExecutorBuilder::default())
            .consensus(EthereumConsensusBuilder::default())
            .engine_validator(EthereumEngineValidatorBuilder::default())
    }
}

impl NodeTypes for TelosNode {
    type Primitives = ();
    type ChainSpec = ChainSpec;
}

impl NodeTypesWithEngine for TelosNode {
    type Engine = EthEngineTypes;
}

/// Add-ons for Telos
#[derive(Debug, Clone)]
pub struct TelosAddOns;

impl<N: FullNodeComponents> NodeAddOns<N> for TelosAddOns {
    type EthApi = TelosEthApi<N>;
}

impl<Types, N> Node<N> for TelosNode
where
    Types: NodeTypesWithEngine<Engine = EthEngineTypes, ChainSpec = ChainSpec>,
    N: FullNodeTypes<Types = Types>,
{
    type ComponentsBuilder = ComponentsBuilder<
        N,
        EthereumPoolBuilder,
        EthereumPayloadBuilder,
        EthereumNetworkBuilder,
        EthereumExecutorBuilder,
        EthereumConsensusBuilder,
        EthereumEngineValidatorBuilder,
    >;

    type AddOns = TelosAddOns;

    fn components_builder(&self) -> Self::ComponentsBuilder {
        Self::components()
    }
}
