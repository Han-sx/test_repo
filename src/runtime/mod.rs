// Copyright 2019-2020 ChainX Project Authors. Licensed under GPL-3.0.

pub mod frame;
pub mod primitives;

use frame::xgateway_bitcoin::BtcTxResult;
use frame::xgateway_bitcoin::BtcTxState;
use frame::xgateway_bitcoin::BtcTxType;
use frame::xgateway_records::WithdrawalRecord;
use frame::xgateway_records::WithdrawalRecordId;
use sp_core::H256;
use sp_runtime::traits::BlakeTwo256;

pub use subxt::Signer;
use subxt::{
    balances::{AccountData, Balances},
    extrinsic::DefaultExtra,
    register_default_type_sizes,
    system::System,
    EventTypeRegistry, PairSigner, Runtime,
};

use self::{
    frame::{
        xgateway_bitcoin::{XGatewayBitcoin, XGatewayBitcoinEventTypeRegistry},
        xgateway_bitcoin_v2::{XGatewayBitcoinV2, XGatewayBitcoinV2EventTypeRegistry},
        xgateway_common::{XGatewayCommon, XGatewayCommonEventTypeRegistry},
        xgateway_records::{XGatewayRecords, XGatewayRecordsEventTypeRegistry},
        xsystem::{XSystem, XSystemEventTypeRegistry},
    },
    primitives::{
        AccountId, Address, Balance, BlockNumber, Extrinsic, Hash, Header, Index, Signature,
    },
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ChainXNodeRuntime;

impl Runtime for ChainXNodeRuntime {
    type Signature = Signature;
    type Extra = ChainXExtra<Self>;

    fn register_type_sizes(event_type_registry: &mut EventTypeRegistry<Self>) {
        event_type_registry.with_x_system();
        event_type_registry.with_x_gateway_common();
        event_type_registry.with_x_gateway_records();
        event_type_registry.with_x_gateway_bitcoin();
        event_type_registry.with_x_gateway_bitcoin_v2();

        //x_system
        event_type_registry.register_type_size::<H256>("H256");
        event_type_registry.register_type_size::<BtcTxResult>("BtcTxResult");
        event_type_registry.register_type_size::<BtcTxType>("BtcTxType");
        event_type_registry.register_type_size::<BtcTxState>("BtcTxState");

        //x_gateway_records
        event_type_registry.register_type_size::<WithdrawalRecordId>("WithdrawalRecordId");
        event_type_registry.register_type_size::<WithdrawalRecord<
            <Self as System>::AccountId,
            <Self as Balances>::Balance,
            <Self as System>::BlockNumber,
        >>("WithdrawalRecord");

        event_type_registry.register_type_size::<Balance>("Balance");
        event_type_registry.register_type_size::<Balance>("AmountOf<T>");
        event_type_registry.register_type_size::<Balance>("BalanceOf<T>");
        event_type_registry.register_type_size::<AccountId>("AccountId");
        event_type_registry.register_type_size::<AccountId>("T::AccountId");
        event_type_registry
            .register_type_size::<AccountId>("<T as frame_system::Config>::AccountId");

        event_type_registry.register_type_size::<BlockNumber>("BlockNumber");
        event_type_registry.register_type_size::<BlockNumber>("BlockNumberFor<T>");
        event_type_registry.register_type_size::<u8>("AssetType");
        event_type_registry.register_type_size::<u8>("Chain");
        event_type_registry.register_type_size::<u8>("CurrencyIdOf<T>");
        event_type_registry.register_type_size::<Hash>("Hash");
        event_type_registry.register_type_size::<u32>("SessionIndex");
        event_type_registry.register_type_size::<u32>("TradingPairId");
        event_type_registry.register_type_size::<u32>("PriceFluctuation");

        // mock
        event_type_registry.register_type_size::<Vec<u8>>("WithdrawalState");
        event_type_registry.register_type_size::<Vec<u8>>("TradingPrice");
        event_type_registry.register_type_size::<Vec<u8>>("TradingPairProfile");
        event_type_registry.register_type_size::<Vec<u8>>("Percent");
        event_type_registry.register_type_size::<Vec<u8>>("GenericTrusteeIntentionProps");
        event_type_registry.register_type_size::<Vec<u8>>("GenericTrusteeSessionInfo<AccountId>");
        event_type_registry.register_type_size::<Vec<u8>>("IdentificationTuple");
        event_type_registry.register_type_size::<Vec<u8>>("OpaqueTimeSlot");
        event_type_registry.register_type_size::<Vec<u8>>(
            "OrderExecutedInfo<AccountId, Balance, BlockNumber, Price>",
        );
        event_type_registry.register_type_size::<Vec<u8>>(
            "Order<TradingPairId, AccountId, Balance, Price, BlockNumber>",
        );

        register_default_type_sizes(event_type_registry);
    }
}

impl System for ChainXNodeRuntime {
    type Index = Index;
    type BlockNumber = BlockNumber;
    type Hash = Hash;
    type Hashing = BlakeTwo256;
    type AccountId = AccountId;
    type Address = Address;
    type Header = Header;
    type Extrinsic = Extrinsic;
    type AccountData = AccountData<<Self as Balances>::Balance>;
}

impl Balances for ChainXNodeRuntime {
    type Balance = Balance;
}

impl XSystem for ChainXNodeRuntime {}

impl XGatewayCommon for ChainXNodeRuntime {}

impl XGatewayBitcoin for ChainXNodeRuntime {}

impl XGatewayRecords for ChainXNodeRuntime {}

impl XGatewayBitcoinV2 for ChainXNodeRuntime {}

/// ChainX `SignedExtra` for ChainX runtime.
pub type ChainXExtra<T> = DefaultExtra<T>;

/// ChainX `Pair` for ChainX runtime.
pub type ChainXPair = sp_core::sr25519::Pair;

/// ChainX `PairSigner` for ChainX runtime.
pub type ChainXPairSigner = PairSigner<ChainXNodeRuntime, ChainXPair>;
