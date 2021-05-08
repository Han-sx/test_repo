// Copyright 2019-2020 ChainX Project Authors. Licensed under GPL-3.0.

use std::{fmt::Debug, marker::PhantomData};

use codec::{Decode, Encode};
use subxt::{balances::Balances, system::System, Store};

use crate::runtime::primitives::{Amount, AssetId, Decimals};
use subxt::module;

// ============================================================================
// Module
// ============================================================================

/// The subset of the `xpallet_system::Trait`.
#[module]
pub trait XSystem: System + Balances {}

// ============================================================================
// Storage
// ============================================================================

/// NetworkProps field of the `XSystem` module.
#[derive(Clone, Debug, Eq, PartialEq, Encode, Store)]
pub struct NetworkPropsStore<T: XSystem> {
    #[store(returns = NetworkType)]
    /// Runtime marker.
    pub _runtime: PhantomData<T>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Encode, Decode)]
pub enum NetworkType {
    Mainnet,
    Testnet,
}

impl Default for NetworkType {
    fn default() -> Self {
        NetworkType::Testnet
    }
}

// ============================================================================
// Call
// ============================================================================

// ============================================================================
// Event
// ============================================================================
