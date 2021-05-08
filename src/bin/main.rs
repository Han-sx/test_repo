// Copyright 2019-2020 ChainX Project Authors. Licensed under GPL-3.0.

use btc_relay::{logger, CmdConfig, Result, Service};

#[tokio::main]
async fn main() -> Result<()> {
    let conf = CmdConfig::init()?;

    logger::init(&conf)?;

    Service::relay(conf).await?;

    Ok(())
}
