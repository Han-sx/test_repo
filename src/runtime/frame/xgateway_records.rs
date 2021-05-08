// Copyright 2019-2020 ChainX Project Authors. Licensed under GPL-3.0.

use codec::{Decode, Encode};

use crate::runtime::{frame::xsystem::XSystem, primitives::AssetId};

use subxt::module;

// ============================================================================
// Module
// ============================================================================

/// The subset of the `xpallet_gateway::records::Trait`.
#[module]
pub trait XGatewayRecords: XSystem {}

pub type WithdrawalRecordId = u32;

#[derive(PartialEq, Eq, Clone, Debug, Default, Encode, Decode)]
pub struct WithdrawalRecord<AccountId, Balance, BlockNumber> {
    asset_id: AssetId,
    applicant: AccountId,
    balance: Balance,
    addr: Vec<u8>,
    ext: Vec<u8>,
    height: BlockNumber,
}

#[derive(PartialEq, Eq, Clone, Copy, Debug, Encode, Decode)]
pub enum WithdrawalState {
    Applying,
    Processing,
    NormalFinish,
    RootFinish,
    NormalCancel,
    RootCancel,
}

impl Default for WithdrawalState {
    fn default() -> Self {
        WithdrawalState::Applying
    }
}

// ============================================================================
// Storage
// ============================================================================

// ============================================================================
// Call
// ============================================================================

// ============================================================================
// Event
// ============================================================================
