// Copyright 2019-2020 ChainX Project Authors. Licensed under GPL-3.0.

use std::{convert::TryFrom, marker::PhantomData};

use codec::{Decode, Encode};
use futures::future::BoxFuture;
use subxt::{module, Store};

use crate::runtime::frame::xsystem::XSystem;

#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
pub struct TrusteeIntentionProps<TrusteeEntity: BytesLike> {
    pub about: Vec<u8>,
    pub hot_entity: TrusteeEntity,
    pub cold_entity: TrusteeEntity,
}

// ============================================================================
// Module
// ============================================================================

/// The subset of the `xpallet_gateway::common::Trait`.
#[module]
pub trait XGatewayCommon: XSystem {}

// ============================================================================
// Storage
// ============================================================================

/// TrusteeSessionInfoLen field of the `XGatewayCommon` module.
/// when generate trustee, auto generate a new session number, increase the newest trustee addr, can't modify by user
#[derive(Clone, Debug, Eq, PartialEq, Encode, Store)]
pub struct TrusteeSessionInfoLenStore<'a, T: XGatewayCommon> {
    #[store(returns = u32)]
    /// Runtime marker.
    pub _runtime: PhantomData<T>,
    /// Chain to retrieve the `TrusteeSessionInfoLen<T>` for.
    pub chain: &'a Chain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd, Encode, Decode)]
pub enum Chain {
    ChainX,
    Bitcoin,
    Ethereum,
    Polkadot,
}

impl Default for Chain {
    fn default() -> Self {
        Chain::ChainX
    }
}

/// TrusteeSessionInfoOf field of the `XGatewayCommon` module.
// #[derive(Clone, Debug, Eq, PartialEq, Encode, Store)]
#[derive(Clone, Debug, Eq, PartialEq, Encode)]
pub struct TrusteeSessionInfoOfStore<'a, T: XGatewayCommon> {
    // #[store(returns = GenericTrusteeSessionInfo<T::AccountId>)]
    /// Runtime marker.
    pub _runtime: PhantomData<T>,
    /// Chain to retrieve the `TrusteeSessionInfoOf<T>` for.
    pub chain: &'a Chain,
    /// Session number to retrieve the `TrusteeSessionInfoOf<T>` for.
    pub number: &'a u32,
}

impl<'a, T: XGatewayCommon> subxt::Store<T> for TrusteeSessionInfoOfStore<'a, T> {
    const MODULE: &'static str = MODULE;
    const FIELD: &'static str = "TrusteeSessionInfoOf";
    type Returns = GenericTrusteeSessionInfo<T::AccountId>;
    fn prefix(
        metadata: &subxt::Metadata,
    ) -> Result<subxt::sp_core::storage::StorageKey, subxt::MetadataError> {
        Ok(metadata
            .module(Self::MODULE)?
            .storage(Self::FIELD)?
            .prefix())
    }
    fn key(
        &self,
        metadata: &subxt::Metadata,
    ) -> Result<subxt::sp_core::storage::StorageKey, subxt::MetadataError> {
        Ok(metadata
            .module(Self::MODULE)?
            .storage(Self::FIELD)?
            .double_map()?
            .key(&self.chain, &self.number))
    }
}

/// Store extension trait.
pub trait TrusteeSessionInfoOfStoreExt<T: subxt::Runtime + XGatewayCommon> {
    /// Retrieve the store element.
    fn trustee_session_info_of<'a>(
        &'a self,
        chain: &'a Chain,
        number: &'a u32,
        hash: Option<T::Hash>,
    ) -> BoxFuture<'a, Result<Option<GenericTrusteeSessionInfo<T::AccountId>>, subxt::Error>>;
    /// Iterate over the store element.
    fn trustee_session_info_of_iter(
        &self,
        hash: Option<T::Hash>,
    ) -> BoxFuture<'_, Result<subxt::KeyIter<T, TrusteeSessionInfoOfStore<T>>, subxt::Error>>;
}

impl<T: subxt::Runtime + XGatewayCommon> TrusteeSessionInfoOfStoreExt<T> for subxt::Client<T> {
    fn trustee_session_info_of<'a>(
        &'a self,
        chain: &'a Chain,
        number: &'a u32,
        hash: Option<T::Hash>,
    ) -> BoxFuture<'a, Result<Option<GenericTrusteeSessionInfo<T::AccountId>>, subxt::Error>> {
        let _runtime = core::marker::PhantomData::<T>;
        Box::pin(async move {
            self.fetch(
                &TrusteeSessionInfoOfStore {
                    _runtime,
                    chain,
                    number,
                },
                hash,
            )
            .await
        })
    }
    fn trustee_session_info_of_iter(
        &self,
        hash: Option<T::Hash>,
    ) -> BoxFuture<'_, Result<subxt::KeyIter<T, TrusteeSessionInfoOfStore<T>>, subxt::Error>> {
        Box::pin(self.iter(hash))
    }
}

#[derive(PartialEq, Eq, Clone, Debug, Encode, Decode)]
pub struct GenericTrusteeSessionInfo<AccountId>(pub TrusteeSessionInfo<AccountId, Vec<u8>>);

// pub type BtcTrusteeSessionInfo<AccountId> = TrusteeSessionInfo<AccountId, BtcTrusteeAddrInfo>;

#[derive(PartialEq, Eq, Clone, Debug, Encode, Decode)]
pub struct TrusteeSessionInfo<AccountId, TrusteeAddress: BytesLike> {
    pub trustee_list: Vec<AccountId>,
    pub threshold: u16,
    pub hot_address: TrusteeAddress,
    pub cold_address: TrusteeAddress,
}

pub trait BytesLike: Into<Vec<u8>> + TryFrom<Vec<u8>> {}
impl<T: Into<Vec<u8>> + TryFrom<Vec<u8>>> BytesLike for T {}

#[derive(PartialEq, Eq, Clone, Debug, Encode, Decode)]
pub struct BtcTrusteeAddrInfo {
    pub addr: Vec<u8>,
    pub redeem_script: Vec<u8>,
}

impl TryFrom<Vec<u8>> for BtcTrusteeAddrInfo {
    type Error = codec::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Decode::decode(&mut &value[..])
    }
}

impl Into<Vec<u8>> for BtcTrusteeAddrInfo {
    fn into(self) -> Vec<u8> {
        self.encode()
    }
}

// ============================================================================
// Call
// ============================================================================

// ============================================================================
// Event
// ============================================================================
