//! Helper type that represents one of two possible executor types

use core::fmt::Display;

use crate::{
    execute::{BatchExecutor, BlockExecutorProvider, Executor},
    system_calls::OnStateHook,
};
use alloc::boxed::Box;
use alloy_primitives::BlockNumber;
use reth_prune_types::PruneModes;
use reth_storage_errors::provider::ProviderError;
#[cfg(feature = "telos")]
use reth_telos_rpc_engine_api::structs::TelosEngineAPIExtraFields;
use revm_primitives::db::Database;

// re-export Either
pub use futures_util::future::Either;
use revm::State;

impl<A, B> BlockExecutorProvider for Either<A, B>
where
    A: BlockExecutorProvider,
    B: BlockExecutorProvider<Primitives = A::Primitives>,
{
    type Primitives = A::Primitives;

    type Executor<DB: Database<Error: Into<ProviderError> + Display>> =
        Either<A::Executor<DB>, B::Executor<DB>>;

    type BatchExecutor<DB: Database<Error: Into<ProviderError> + Display>> =
        Either<A::BatchExecutor<DB>, B::BatchExecutor<DB>>;

    fn executor<DB>(&self, db: DB) -> Self::Executor<DB>
    where
        DB: Database<Error: Into<ProviderError> + Display>,
    {
        match self {
            Self::Left(a) => Either::Left(a.executor(db)),
            Self::Right(b) => Either::Right(b.executor(db)),
        }
    }

    fn batch_executor<DB>(&self, db: DB) -> Self::BatchExecutor<DB>
    where
        DB: Database<Error: Into<ProviderError> + Display>,
    {
        match self {
            Self::Left(a) => Either::Left(a.batch_executor(db)),
            Self::Right(b) => Either::Right(b.batch_executor(db)),
        }
    }
}

impl<A, B, DB> Executor<DB> for Either<A, B>
where
    A: Executor<DB>,
    B: for<'a> Executor<DB, Input<'a> = A::Input<'a>, Output = A::Output, Error = A::Error>,
    DB: Database<Error: Into<ProviderError> + Display>,
{
    type Input<'a> = A::Input<'a>;
    type Output = A::Output;
    type Error = A::Error;

    fn init(&mut self, tx_env_overrides: Box<dyn crate::TxEnvOverrides>) {
        match self {
            Self::Left(a) => a.init(tx_env_overrides),
            Self::Right(b) => b.init(tx_env_overrides),
        }
    }

    fn execute(self, input: Self::Input<'_>, #[cfg(feature = "telos")] telos_extra_fields: Option<TelosEngineAPIExtraFields>) -> Result<Self::Output, Self::Error> {
        match self {
            Self::Left(a) => a.execute(input, #[cfg(feature = "telos")] telos_extra_fields),
            Self::Right(b) => b.execute(input, #[cfg(feature = "telos")] telos_extra_fields),
        }
    }

    fn execute_with_state_closure<F>(
        self,
        input: Self::Input<'_>,
        witness: F,
        #[cfg(feature = "telos")]
        telos_extra_fields: Option<TelosEngineAPIExtraFields>,
    ) -> Result<Self::Output, Self::Error>
    where
        F: FnMut(&State<DB>),
    {
        match self {
            Self::Left(a) => a.execute_with_state_closure(input, witness, #[cfg(feature = "telos")] telos_extra_fields),
            Self::Right(b) => b.execute_with_state_closure(input, witness, #[cfg(feature = "telos")] telos_extra_fields),
        }
    }

    fn execute_with_state_hook<F>(
        self,
        input: Self::Input<'_>,
        state_hook: F,
        #[cfg(feature = "telos")]
        telos_extra_fields: Option<TelosEngineAPIExtraFields>,
    ) -> Result<Self::Output, Self::Error>
    where
        F: OnStateHook + 'static,
    {
        match self {
            Self::Left(a) => a.execute_with_state_hook(input, state_hook, #[cfg(feature = "telos")] telos_extra_fields),
            Self::Right(b) => b.execute_with_state_hook(input, state_hook, #[cfg(feature = "telos")] telos_extra_fields),
        }
    }
}

impl<A, B, DB> BatchExecutor<DB> for Either<A, B>
where
    A: BatchExecutor<DB>,
    B: for<'a> BatchExecutor<DB, Input<'a> = A::Input<'a>, Output = A::Output, Error = A::Error>,
    DB: Database<Error: Into<ProviderError> + Display>,
{
    type Input<'a> = A::Input<'a>;
    type Output = A::Output;
    type Error = A::Error;

    fn execute_and_verify_one(&mut self, input: Self::Input<'_>) -> Result<(), Self::Error> {
        match self {
            Self::Left(a) => a.execute_and_verify_one(input),
            Self::Right(b) => b.execute_and_verify_one(input),
        }
    }

    fn finalize(self) -> Self::Output {
        match self {
            Self::Left(a) => a.finalize(),
            Self::Right(b) => b.finalize(),
        }
    }

    fn set_tip(&mut self, tip: BlockNumber) {
        match self {
            Self::Left(a) => a.set_tip(tip),
            Self::Right(b) => b.set_tip(tip),
        }
    }

    fn set_prune_modes(&mut self, prune_modes: PruneModes) {
        match self {
            Self::Left(a) => a.set_prune_modes(prune_modes),
            Self::Right(b) => b.set_prune_modes(prune_modes),
        }
    }

    fn size_hint(&self) -> Option<usize> {
        match self {
            Self::Left(a) => a.size_hint(),
            Self::Right(b) => b.size_hint(),
        }
    }
}
