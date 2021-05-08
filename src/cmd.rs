// Copyright 2019-2020 ChainX Project Authors. Licensed under GPL-3.0.

use std::{
    fs::File,
    path::{Path, PathBuf},
};

use log::LevelFilter;
use serde::Deserialize;
use structopt::StructOpt;
use url::Url;

use crate::error::Result;

#[derive(Clone, Debug, StructOpt)]
#[structopt(author, about)]
pub struct CmdConfig {
    #[structopt(short, long, value_name = "FILE", default_value = "config.json")]
    pub config: PathBuf,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Config {
    /// Specify the HTTP url with basic auth of Bitcoin node, like http://user:password@127.0.0.1:8332
    pub btc_url: Url,
    /// Specify the time interval of waiting for the latest Bitcoin block, unit: second
    pub btc_block_interval: u64,

    /// Specify the WebSocket url of ChainX node, like ws://127.0.0.1:8087
    pub chainx_url: Url,
    /// Specify the phrase of ChainX signer for btc relay, like '12 words' or '12 words + //Alice'
    pub chainx_signer: String,
    /// Specify whether to submit block header only, default: submit the whole block
    pub only_header: bool,

    /// Specify the log file path
    pub log_path: PathBuf,
    /// Specify the level of log, like: "OFF", "ERROR", "WARN", "INFO", "DEBUG", "TRACE"
    pub log_level: LevelFilter,
    /// Specify the roll size of log, unit: MB
    pub log_roll_size: u64,
    /// Specify the roll count of log
    pub log_roll_count: u32,

    /// Specify the timeout of RPC request, unit: second
    pub rpc_timeout: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            btc_url: "http://user:password@127.0.0.1:8332".parse().unwrap(),
            btc_block_interval: 120,
            chainx_url: "ws://127.0.0.1:8087".parse().unwrap(),
            chainx_signer: format!("{}//Alice", sp_core::crypto::DEV_PHRASE),
            only_header: true,
            log_path: Path::new("log/btc_relay.log").to_path_buf(),
            log_level: LevelFilter::Debug,
            log_roll_size: 100,
            log_roll_count: 5,
            rpc_timeout: 15,
        }
    }
}

impl CmdConfig {
    /// Generate config from command.
    pub fn init() -> Result<Config> {
        let cmd: CmdConfig = CmdConfig::from_args();
        let file = File::open(cmd.config)?;
        Ok(serde_json::from_reader(file)?)
    }
}
