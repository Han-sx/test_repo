// Copyright 2019-2020 ChainX Project Authors. Licensed under GPL-3.0.

use std::marker::PhantomData;

use codec::{Decode, Encode};
use futures::future::BoxFuture;
use subxt::{module, Call, Store};

use light_bitcoin::{
    chain::{BlockHeader as BtcBlockHeader, Transaction as BtcTransaction},
    keys::Network as BtcNetwork,
    merkle::PartialMerkleTree,
    primitives::H256,
};

use crate::runtime::frame::xsystem::XSystem;

// ============================================================================
// Module
// ============================================================================

/// The subset of the `xpallet_gateway::bitcoin::Trait`.
#[module]
pub trait XGatewayBitcoin: XSystem {}

// ============================================================================
// Storage
// ============================================================================

/// NetworkId field of the `XGatewayBitcoin` module.
#[derive(Clone, Debug, Eq, PartialEq, Encode, Store)]
pub struct NetworkIdStore<T: XGatewayBitcoin> {
    #[store(returns = BtcNetwork)]
    /// Runtime marker.
    pub _runtime: PhantomData<T>,
}

/// BtcWithdrawalFee field of the `XGatewayBitcoin` module.
#[derive(Clone, Debug, Eq, PartialEq, Encode, Store)]
pub struct BtcWithdrawalFeeStore<T: XGatewayBitcoin> {
    #[store(returns = u64)]
    /// Runtime marker.
    pub _runtime: PhantomData<T>,
}

/// BtcMinDeposit field of the `XGatewayBitcoin` module.
#[derive(Clone, Debug, Eq, PartialEq, Encode, Store)]
pub struct BtcMinDepositStore<T: XGatewayBitcoin> {
    #[store(returns = u64)]
    /// Runtime marker.
    pub _runtime: PhantomData<T>,
}

/// BestIndex field of the `XGatewayBitcoin` module.
#[derive(Clone, Debug, Eq, PartialEq, Encode, Store)]
pub struct BestIndexStore<T: XGatewayBitcoin> {
    #[store(returns = BtcHeaderIndex)]
    /// Runtime marker.
    pub _runtime: PhantomData<T>,
}

/// ConfirmedIndex field of the `XGatewayBitcoin` module.
// #[derive(Clone, Debug, Eq, PartialEq, Encode, Store)]
#[derive(Clone, Debug, Eq, PartialEq, Encode)]
pub struct ConfirmedIndexStore<T: XGatewayBitcoin> {
    // #[store(returns = BtcHeaderIndex)]
    /// Runtime marker.
    pub _runtime: PhantomData<T>,
}

impl<T: XGatewayBitcoin> subxt::Store<T> for ConfirmedIndexStore<T> {
    const MODULE: &'static str = MODULE;
    const FIELD: &'static str = "ConfirmedIndex";
    type Returns = BtcHeaderIndex;
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
            .plain()?
            .key())
    }
}

/// Store extension trait.
pub trait ConfirmedIndexStoreExt<T: subxt::Runtime + XGatewayBitcoin> {
    /// Retrieve the store element.
    fn confirmed_index(
        &self,
        hash: Option<T::Hash>,
    ) -> BoxFuture<'_, Result<Option<BtcHeaderIndex>, subxt::Error>>;
    /// Iterate over the store element.
    fn confirmed_index_iter(
        &self,
        hash: Option<T::Hash>,
    ) -> BoxFuture<'_, Result<subxt::KeyIter<T, ConfirmedIndexStore<T>>, subxt::Error>>;
}
impl<T: subxt::Runtime + XGatewayBitcoin> ConfirmedIndexStoreExt<T> for subxt::Client<T> {
    fn confirmed_index(
        &self,
        hash: Option<T::Hash>,
    ) -> BoxFuture<'_, Result<Option<BtcHeaderIndex>, subxt::Error>> {
        let _runtime = core::marker::PhantomData::<T>;
        Box::pin(async move { self.fetch(&ConfirmedIndexStore { _runtime }, hash).await })
    }
    fn confirmed_index_iter(
        &self,
        hash: Option<T::Hash>,
    ) -> BoxFuture<'_, Result<subxt::KeyIter<T, ConfirmedIndexStore<T>>, subxt::Error>> {
        Box::pin(self.iter(hash))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Encode, Decode)]
pub struct BtcHeaderIndex {
    pub hash: H256,
    pub height: u32,
}

/// BlockHashFor field of the `XGatewayBitcoin` module.
#[derive(Clone, Debug, Eq, PartialEq, Encode, Store)]
pub struct BlockHashForStore<T: XGatewayBitcoin> {
    #[store(returns = Vec<H256>)]
    /// Runtime marker.
    pub _runtime: PhantomData<T>,
    /// Height to retrieve the `Vec<H256>` for.
    pub height: u32,
}

/*
impl<T: XGatewayBitcoin> subxt::Store<T> for BlockHashForStore<T> {
    const MODULE: &'static str = MODULE;
    const FIELD: &'static str = "BlockHashFor";
    type Returns = Vec<H256>;
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
            .map()?
            .key(&self.height))
    }
}

/// Store extension trait.
pub trait BlockHashForStoreExt<T: subxt::Runtime + XGatewayBitcoin> {
    /// Retrieve the store element.
    fn block_hash_for(
        &self,
        height: u32,
        hash: Option<T::Hash>,
    ) -> BoxFuture<'_, Result<Vec<H256>, subxt::Error>>;
    /// Iterate over the store element.
    fn block_hash_for_iter(
        &self,
        hash: Option<T::Hash>,
    ) -> BoxFuture<'_, Result<subxt::KeyIter<T, BlockHashForStore<T>>, subxt::Error>>;
}
impl<T: subxt::Runtime + XGatewayBitcoin> BlockHashForStoreExt<T> for subxt::Client<T> {
    fn block_hash_for(
        &self,
        height: u32,
        hash: Option<T::Hash>,
    ) -> BoxFuture<'_, Result<Vec<H256>, subxt::Error>> {
        let _runtime = core::marker::PhantomData::<T>;
        Box::pin(async move {
            self.fetch_or_default(&BlockHashForStore { _runtime, height }, hash)
                .await
        })
    }

    fn block_hash_for_iter(
        &self,
        hash: Option<T::Hash>,
    ) -> BoxFuture<'_, Result<subxt::KeyIter<T, BlockHashForStore<T>>, subxt::Error>> {
        Box::pin(self.iter(hash))
    }
}
*/

/// Headers field of the `XGatewayBitcoin` module.
// #[derive(Clone, Debug, Eq, PartialEq, Encode, Store)]
#[derive(Clone, Debug, Eq, PartialEq, Encode)]
pub struct HeadersStore<'a, T: XGatewayBitcoin> {
    // #[store(returns = BtcHeaderInfo)]
    /// Runtime marker.
    pub _runtime: PhantomData<T>,
    /// Headers to retrieve the `Option<BtcHeaderInfo>` for.
    pub block_hash: &'a H256,
}

impl<'a, T: XGatewayBitcoin> subxt::Store<T> for HeadersStore<'a, T> {
    const MODULE: &'static str = MODULE;
    const FIELD: &'static str = "Headers";
    type Returns = BtcHeaderInfo;
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
            .map()?
            .key(&self.block_hash))
    }
}

/// Store extension trait.
pub trait HeadersStoreExt<T: subxt::Runtime + XGatewayBitcoin> {
    /// Retrieve the store element.
    fn headers<'a>(
        &'a self,
        block_hash: &'a H256,
        hash: Option<T::Hash>,
    ) -> BoxFuture<'a, Result<Option<BtcHeaderInfo>, subxt::Error>>;
    /// Iterate over the store element.
    fn headers_iter(
        &self,
        hash: Option<T::Hash>,
    ) -> BoxFuture<Result<subxt::KeyIter<T, HeadersStore<T>>, subxt::Error>>;
}
impl<T: subxt::Runtime + XGatewayBitcoin> HeadersStoreExt<T> for subxt::Client<T> {
    fn headers<'a>(
        &'a self,
        block_hash: &'a H256,
        hash: Option<T::Hash>,
    ) -> BoxFuture<'a, Result<Option<BtcHeaderInfo>, subxt::Error>> {
        let _runtime = core::marker::PhantomData::<T>;
        Box::pin(async move {
            self.fetch(
                &HeadersStore {
                    _runtime,
                    block_hash,
                },
                hash,
            )
            .await
        })
    }
    fn headers_iter(
        &self,
        hash: Option<T::Hash>,
    ) -> BoxFuture<Result<subxt::KeyIter<T, HeadersStore<T>>, subxt::Error>> {
        Box::pin(self.iter(hash))
    }
}

/// Headers field of the `XGatewayBitcoin` module.
// #[derive(Clone, Debug, Eq, PartialEq, Encode, Store)]
#[derive(Clone, Debug, Eq, PartialEq, Encode)]
pub struct TxStateStore<'a, T: XGatewayBitcoin> {
    // #[store(returns = BtcHeaderInfo)]
    /// Runtime marker.
    pub _runtime: PhantomData<T>,
    /// Headers to retrieve the `Option<BtcHeaderInfo>` for.
    pub tx_hash: &'a H256,
}

impl<'a, T: XGatewayBitcoin> subxt::Store<T> for TxStateStore<'a, T> {
    const MODULE: &'static str = MODULE;
    const FIELD: &'static str = "TxState";
    type Returns = BtcTxState;
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
            .map()?
            .key(&self.tx_hash))
    }
}

/// Store extension trait.
pub trait TxStateStoreExt<T: subxt::Runtime + XGatewayBitcoin> {
    /// Retrieve the store element.
    fn states<'a>(
        &'a self,
        tx_hash: &'a H256,
        hash: Option<T::Hash>,
    ) -> BoxFuture<'a, Result<Option<BtcTxState>, subxt::Error>>;
    /// Iterate over the store element.
    fn state_iter(
        &self,
        hash: Option<T::Hash>,
    ) -> BoxFuture<Result<subxt::KeyIter<T, TxStateStore<T>>, subxt::Error>>;
}
impl<T: subxt::Runtime + XGatewayBitcoin> TxStateStoreExt<T> for subxt::Client<T> {
    fn states<'a>(
        &'a self,
        tx_hash: &'a H256,
        hash: Option<T::Hash>,
    ) -> BoxFuture<'a, Result<Option<BtcTxState>, subxt::Error>> {
        let _runtime = core::marker::PhantomData::<T>;
        Box::pin(async move { self.fetch(&TxStateStore { _runtime, tx_hash }, hash).await })
    }
    fn state_iter(
        &self,
        hash: Option<T::Hash>,
    ) -> BoxFuture<Result<subxt::KeyIter<T, TxStateStore<T>>, subxt::Error>> {
        Box::pin(self.iter(hash))
    }
}

#[derive(Clone, Debug, PartialEq, Default, Encode, Decode)]
pub struct BtcHeaderInfo {
    pub header: BtcBlockHeader,
    pub height: u32,
}

/// WithdrawalProposal field of the `XGatewayBitcoin` module.
// #[derive(Clone, Debug, Eq, PartialEq, Encode, Store)]
#[derive(Clone, Debug, Eq, PartialEq, Encode)]
pub struct WithdrawalProposalStore<T: XGatewayBitcoin> {
    // #[store(returns = BtcWithdrawalProposal<T::AccountId>)]
    /// Runtime marker.
    pub _runtime: PhantomData<T>,
}

impl<T: XGatewayBitcoin> subxt::Store<T> for WithdrawalProposalStore<T> {
    const MODULE: &'static str = MODULE;
    const FIELD: &'static str = "WithdrawalProposal";
    type Returns = BtcWithdrawalProposal<T::AccountId>;
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
            .plain()?
            .key())
    }
}
/// Store extension trait.
pub trait WithdrawalProposalStoreExt<T: subxt::Runtime + XGatewayBitcoin> {
    /// Retrieve the store element.
    fn withdrawal_proposal(
        &self,
        hash: Option<T::Hash>,
    ) -> BoxFuture<'_, Result<Option<BtcWithdrawalProposal<T::AccountId>>, subxt::Error>>;
    /// Iterate over the store element.
    fn withdrawal_proposal_iter(
        &self,
        hash: Option<T::Hash>,
    ) -> BoxFuture<'_, Result<subxt::KeyIter<T, WithdrawalProposalStore<T>>, subxt::Error>>;
}
impl<T: subxt::Runtime + XGatewayBitcoin> WithdrawalProposalStoreExt<T> for subxt::Client<T> {
    fn withdrawal_proposal(
        &self,
        hash: Option<T::Hash>,
    ) -> BoxFuture<'_, Result<Option<BtcWithdrawalProposal<T::AccountId>>, subxt::Error>> {
        let _runtime = core::marker::PhantomData::<T>;
        Box::pin(async move {
            self.fetch(&WithdrawalProposalStore { _runtime }, hash)
                .await
        })
    }
    fn withdrawal_proposal_iter(
        &self,
        hash: Option<T::Hash>,
    ) -> BoxFuture<'_, Result<subxt::KeyIter<T, WithdrawalProposalStore<T>>, subxt::Error>> {
        Box::pin(self.iter(hash))
    }
}

#[derive(Clone, Debug, PartialEq, Encode, Decode)]
pub struct BtcWithdrawalProposal<AccountId> {
    pub sig_state: VoteResult,
    pub withdrawal_id_list: Vec<u32>,
    pub tx: BtcTransaction,
    pub trustee_list: Vec<(AccountId, bool)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Encode, Decode)]
pub enum VoteResult {
    Unfinish,
    Finish,
}

/// PendingDeposits field of the `XGatewayBitcoin` module.
#[derive(Clone, Debug, Eq, PartialEq, Encode, Store)]
pub struct PendingDepositsStore<'a, T: XGatewayBitcoin> {
    #[store(returns = Vec<BtcDepositCache>)]
    /// Runtime marker.
    pub _runtime: PhantomData<T>,
    /// Headers to retrieve the `Option<BtcHeaderInfo>` for.
    /// unclaimed deposit info, addr => tx_hash, btc value
    pub btc_address: &'a [u8],
}

/*
impl<'a, T: XGatewayBitcoin> subxt::Store<T> for PendingDepositsStore<'a, T> {
    const MODULE: &'static str = MODULE;
    const FIELD: &'static str = "PendingDeposits";
    type Returns = Vec<BtcDepositCache>;
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
            .map()?
            .key(&self.btc_address))
    }
}

/// Store extension trait.
pub trait PendingDepositsStoreExt<T: subxt::Runtime + XGatewayBitcoin> {
    /// Retrieve the store element.
    fn pending_deposits<'a>(
        &'a self,
        btc_address: &'a [u8],
        hash: Option<T::Hash>,
    ) -> BoxFuture<'a, Result<Vec<BtcDepositCache>, subxt::Error>>;
    /// Iterate over the store element.
    fn pending_deposits_iter(
        &self,
        hash: Option<T::Hash>,
    ) -> BoxFuture<'_, Result<subxt::KeyIter<T, PendingDepositsStore<T>>, subxt::Error>>;
}
impl<T: subxt::Runtime + XGatewayBitcoin> PendingDepositsStoreExt<T> for subxt::Client<T> {
    fn pending_deposits<'a>(
        &'a self,
        btc_address: &'a [u8],
        hash: Option<T::Hash>,
    ) -> BoxFuture<'a, Result<Vec<BtcDepositCache>, subxt::Error>> {
        let _runtime = core::marker::PhantomData::<T>;
        Box::pin(async move {
            self.fetch_or_default(
                &PendingDepositsStore {
                    _runtime,
                    btc_address,
                },
                hash,
            )
            .await
        })
    }
    fn pending_deposits_iter(
        &self,
        hash: Option<T::Hash>,
    ) -> BoxFuture<'_, Result<subxt::KeyIter<T, PendingDepositsStore<T>>, subxt::Error>> {
        Box::pin(self.iter(hash))
    }
}
*/

#[derive(PartialEq, Clone, Debug, Default, Encode, Decode)]
pub struct BtcDepositCache {
    pub txid: H256,
    pub balance: u64,
}

/// GenesisInfoStore field of the `XGatewayBitcoin` module.
#[derive(Clone, Debug, Eq, PartialEq, Encode, Store)]
pub struct GenesisInfoStore<T: XGatewayBitcoin> {
    #[store(returns = (BtcBlockHeader, u32))]
    /// Runtime marker.
    pub _runtime: PhantomData<T>,
}

// ============================================================================
// Call
// ============================================================================

/// Arguments for push bitcoin block header
#[derive(Clone, Debug, Eq, PartialEq, Encode, Call)]
pub struct PushHeaderCall<'a, T: XGatewayBitcoin> {
    /// Runtime marker.
    pub _runtime: PhantomData<T>,
    /// Serialized btc header.
    pub header: &'a [u8],
}

/// Arguments for push bitcoin transaction
#[derive(Clone, Debug, Eq, PartialEq, Encode, Call)]
pub struct PushTransactionCall<'a, T: XGatewayBitcoin> {
    /// Runtime marker.
    pub _runtime: PhantomData<T>,
    /// Serialized btc transaction.
    pub tx: &'a [u8],
    ///
    pub relayed_info: &'a BtcRelayedTxInfo,
    /// Serialized btc transaction.
    pub prev_tx: &'a Option<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
pub struct BtcRelayedTxInfo {
    pub block_hash: H256,
    pub merkle_proof: PartialMerkleTree,
}

// ============================================================================
// Event
// ============================================================================

/// Push header event.
// #[derive(Clone, Debug, Eq, PartialEq, Decode, Event)]
#[derive(Clone, Debug, Eq, PartialEq, Decode)]
pub struct PushHeaderEvent<T: XGatewayBitcoin> {
    pub _runtime: PhantomData<T>,
    /// Bitcoin block hash.
    pub block_hash: H256,
}

impl<T: XGatewayBitcoin> subxt::Event<T> for PushHeaderEvent<T> {
    const MODULE: &'static str = MODULE;
    const EVENT: &'static str = "HeaderInserted";
}
/// Event extension trait.
pub trait PushHeaderEventExt<T: XGatewayBitcoin> {
    /// Retrieves the event.
    fn push_header(&self) -> Result<Option<PushHeaderEvent<T>>, codec::Error>;
}
impl<T: XGatewayBitcoin> PushHeaderEventExt<T> for subxt::ExtrinsicSuccess<T> {
    fn push_header(&self) -> Result<Option<PushHeaderEvent<T>>, codec::Error> {
        self.find_event()
    }
}

/// Push transaction event.
// #[derive(Clone, Debug, Eq, PartialEq, Decode, Event)]
#[derive(Clone, Debug, Eq, PartialEq, Decode)]
pub struct PushTransactionEvent<T: XGatewayBitcoin> {
    pub _runtime: PhantomData<T>,
    /// Bitcoin transaction hash.
    pub tx_hash: H256,
    /// Bitcoin block hash.
    pub block_hash: H256,
    /// Bitcoin transaction state (result + tx_type).
    pub tx_state: BtcTxState,
}

impl<T: XGatewayBitcoin> subxt::Event<T> for PushTransactionEvent<T> {
    const MODULE: &'static str = MODULE;
    const EVENT: &'static str = "TxProcessed";
}
/// Event extension trait.
pub trait PushTransactionEventExt<T: XGatewayBitcoin> {
    /// Retrieves the event.
    fn push_transaction(&self) -> Result<Option<PushTransactionEvent<T>>, codec::Error>;
}
impl<T: XGatewayBitcoin> PushTransactionEventExt<T> for subxt::ExtrinsicSuccess<T> {
    fn push_transaction(&self) -> Result<Option<PushTransactionEvent<T>>, codec::Error> {
        self.find_event()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Default, Encode, Decode)]
pub struct BtcTxState {
    pub tx_type: BtcTxType,
    pub result: BtcTxResult,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Encode, Decode)]
pub enum BtcTxResult {
    Success,
    Failed,
}

impl Default for BtcTxResult {
    fn default() -> Self {
        BtcTxResult::Failed
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Encode, Decode)]
pub enum BtcTxType {
    Withdrawal,
    Deposit,
    HotAndCold,
    TrusteeTransition,
    Irrelevance,
}

impl Default for BtcTxType {
    fn default() -> Self {
        BtcTxType::Irrelevance
    }
}
