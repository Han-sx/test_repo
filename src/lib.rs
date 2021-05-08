// Copyright 2019-2020 ChainX Project Authors. Licensed under GPL-3.0.

#![allow(clippy::type_complexity)]

#[macro_use]
pub mod logger;

mod bitcoin;
mod chainx;
mod cmd;
mod error;
mod runtime;
mod service;

#[cfg(test)]
pub(crate) mod mock;

#[cfg(test)]
pub(crate) mod test;

pub use self::bitcoin::Bitcoin;
pub use self::chainx::ChainX;
pub use self::cmd::{CmdConfig, Config};
pub use self::error::{Error, Result};
pub use self::runtime::{ChainXExtra, ChainXNodeRuntime, ChainXPair, ChainXPairSigner};
pub use self::service::Service;
