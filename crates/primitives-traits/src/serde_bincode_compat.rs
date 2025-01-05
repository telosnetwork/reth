use core::fmt::Debug;

pub use super::header::{serde_bincode_compat as header, serde_bincode_compat::*};
use serde::{de::DeserializeOwned, Serialize};

/// Trait for types that can be serialized and deserialized using bincode.
pub trait SerdeBincodeCompat: Sized + 'static {
    /// Serde representation of the type for bincode serialization.
    type BincodeRepr<'a>: Debug + Serialize + DeserializeOwned + From<&'a Self> + Into<Self>;
}

impl SerdeBincodeCompat for alloy_consensus::Header {
    type BincodeRepr<'a> = alloy_consensus::serde_bincode_compat::Header<'a>;
}

#[cfg(feature = "telos")]
impl SerdeBincodeCompat for reth_telos_primitives_traits::TelosHeader {
    type BincodeRepr<'a> = reth_telos_primitives_traits::serde_bincode_compat::TelosHeader<'a>;
}