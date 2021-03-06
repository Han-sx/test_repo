// Copyright 2019-2020 ChainX Project Authors. Licensed under GPL-3.0.

use sp_runtime::traits::{BlakeTwo256, IdentifyAccount, Verify};

/// An index to a block.
pub type BlockNumber = u32;

/// Alias to 512-bit hash when used in the context of a transaction signature on the chain.
pub type Signature = sp_runtime::MultiSignature;

/// Some way of identifying an account on the chain. We intentionally make it equivalent
/// to the public key of our transaction signing scheme.
pub type AccountId = <<Signature as Verify>::Signer as IdentifyAccount>::AccountId;

/// The type for looking up accounts. We don't expect more than 4 billion of them, but you
/// never know...
pub type AccountIndex = u32;

/// Balance of an account.
pub type Balance = u128;

/// Index of a transaction in the chain.
pub type Index = u32;

/// A hash of some data used by the chain.
pub type Hash = sp_core::H256;

/// The address format for describing accounts.
pub type Address = sp_runtime::MultiAddress<AccountId, AccountIndex>;

/// Block header type as expected by this runtime.
pub type Header = sp_runtime::generic::Header<BlockNumber, BlakeTwo256>;

/// Unchecked extrinsic type as expected by this runtime.
pub type Extrinsic = sp_runtime::OpaqueExtrinsic;

/// Signed version of Balance
pub type Amount = i128;

/// Asset ID.
pub type AssetId = u32;

/// Decimal type.
pub type Decimals = u8;
