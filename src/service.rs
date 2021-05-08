// Copyright 2019-2020 ChainX Project Authors. Licensed under GPL-3.0.

use std::net::ToSocketAddrs;
use std::{collections::BTreeMap, time::Duration};

use light_bitcoin::chain::h256_rev;
use light_bitcoin::{
    chain::{Block as BtcBlock, BlockHeader as BtcBlockHeader, Transaction},
    keys::Address as BtcAddress,
    merkle::PartialMerkleTree,
    primitives::{hash_rev, H256},
    serialization::serialize,
};

use sp_core::crypto::Pair as _;
use xp_gateway_bitcoin::{
    AccountExtractor, BtcDepositInfo, BtcTxMetaType, OpReturnExtractor, RequestInfo,
    RequestMetaType, RequestType,
};

use crate::{
    bitcoin::Bitcoin,
    chainx::ChainX,
    cmd::Config,
    error::Result,
    runtime::{
        frame::{
            xgateway_bitcoin::{BtcRelayedTxInfo, BtcTxResult, VoteResult},
            xgateway_bitcoin_v2::{
                ExecuteIssueCallExt, ExecuteRedeemCallExt, IssueRequestsStoreExt,
                RedeemRequestsStoreExt, VaultsStoreExt,
            },
        },
        ChainXPair, ChainXPairSigner, Signer,
    },
};

const BTC_BLOCK_CONFIRM_GAP: u32 = 6;

#[derive(Clone)]
pub struct Service {
    conf: Config,
    chainx: ChainX,
    signer: ChainXPairSigner,
    bitcoin: Bitcoin,

    // +----+      +----+               +----+      +----+               +----+
    // |    | ---> |    | ---> ... ---> |    | ---> |    | ---> ... ---> |    |
    // +----+      +----+               +----+      +----+               +----+
    //   |                                             |                    |
    // confirmed height                           current height      latest height
    // The BTC blocks (confirmed height ~ current height).
    blocks: BTreeMap<u32, BtcBlock>,
    // The confirmed X-BTC block height in the ChainX.
    confirmed_height: u32,
    // The latest X-BTC block height in the ChainX.
    current_height: u32,
    // The X-BTC genesis information in the ChainX.
    btc_genesis: (BtcBlockHeader, u32),
}

impl Service {
    async fn new(conf: Config) -> Result<Service> {
        let chainx_url = &conf.chainx_url;
        info!("[Service|new] Connecting ChainX node: {}", chainx_url);
        let chainx = ChainX::new(chainx_url.as_str(), conf.rpc_timeout).await?;
        info!("[Service|new] Connected ChainX node: {}", chainx_url);

        let pair = ChainXPair::from_string(&conf.chainx_signer, None).unwrap();
        let signer = ChainXPairSigner::new(pair);
        info!("[Service|new] Signer Account: {}", signer.account_id());

        let btc_url = &conf.btc_url;
        info!("[Service|new] Connecting Bitcoin node: {}", btc_url);
        let bitcoin = Bitcoin::new(btc_url.as_str(), conf.rpc_timeout);
        info!("[Service|new] Connected Bitcoin node: {}", btc_url);

        let btc_genesis = chainx.btc_genesis_info().await?;
        let confirmed_height = chainx.btc_confirmed_index().await?.height;
        let best_height = chainx.btc_best_index().await?.height;
        let mut current_height = best_height;
        info!(
            "[Service|new] Confirmed Height: {}, Best Height: {}",
            confirmed_height, best_height
        );
        assert!(best_height - confirmed_height <= BTC_BLOCK_CONFIRM_GAP);

        // Fetch BTC blocks #confirmed_height - #best_height from ChainX network.
        info!(
            "[Service|new] Fetching BTC block hashes (#{}-#{}) from ChainX network",
            confirmed_height, best_height
        );
        let mut hashes = BTreeMap::new();
        for height in confirmed_height..=best_height {
            let hash = chainx.btc_block_hash_for(height).await?;
            hashes.insert(height, hash);
        }

        // Fetch BTC blocks #confirmed_height - #best_height from Bitcoin network.
        info!(
            "[Service|new] Fetching BTC blocks (#{}-#{}) from bitcoin network",
            confirmed_height, best_height
        );
        // Get the btc blocks that we need.
        let mut blocks = BTreeMap::new();
        for height in confirmed_height..=best_height {
            let block = bitcoin.block_by_height(height).await?;
            // need to check if there is a fork block
            let hash_in_chainx = hashes.get(&height).expect("the height must exist; qed");
            if hash_in_chainx.contains(&block.hash()) {
                blocks.insert(height, block);
                current_height = height;
            } else {
                let hash_in_chainx = hash_in_chainx
                    .iter()
                    .map(|hash| hash_rev(*hash))
                    .collect::<Vec<_>>();
                let hash_in_bitcoin = hash_rev(block.hash());
                warn!(
                    "[Service|new] The BTC block #{} on the Bitcoin network and the ChainX network does not match, \
                    there may be a fork block on ChainX network, we need to resubmit this block, \
                    BTC block #{} hash in ChainX ({:?}), BTC block #{} hash in Bitcoin ({:?})",
                    height, height, hash_in_chainx, height, hash_in_bitcoin
                );
            }
        }
        info!(
            "[Service|new] BTC Blocks: {:?}",
            blocks
                .iter()
                .map(|(height, block)| (height, hash_rev(block.hash())))
                .collect::<Vec<_>>()
        );

        Ok(Self {
            conf,
            chainx,
            signer,
            bitcoin,
            blocks,
            confirmed_height,
            current_height,
            btc_genesis,
        })
    }

    pub async fn relay(conf: Config) -> Result<()> {
        loop {
            let conf = conf.clone();
            let mut service = Self::new(conf).await?;
            info!(
                "[Service|relay] Start to relay the Bitcoin block into the ChainX network, \
                Confirmed X-BTC Block #{}, Current X-BTC Block #{}",
                service.confirmed_height, service.current_height
            );
            let handle = service.run().await;
            match handle {
                Ok(_) => error!("[Service|relay] Relay service exits unexpectedly"),
                Err(err) => error!("[Service|relay] Relay service error: {:?}", err),
            }
            info!("[Service|relay] New relay service will restart after 15s");
            tokio::time::delay_for(Duration::from_secs(15)).await;
        }
    }

    async fn run(&mut self) -> Result<()> {
        // Check for missing transactions
        if !self.conf.only_header {
            let confirmed_block = self.confirmed_block();
            self.push_xbtc_transaction(confirmed_block).await?;
        }
        let mut new_height = self.current_height + 1;
        loop {
            // If there is a BTC withdraw transaction, broadcast it to the BTC network
            // until the storage of withdrawal proposal is removed.
            if let Err(err) = self.check_and_send_btc_withdrawal_proposal().await {
                error!(
                    "[Service|run] Check and Send BTC withdrawal proposal error: {}",
                    err
                );
                tokio::time::delay_for(Duration::from_secs(2)).await;
                continue;
            }

            // ================================================================

            // Get new block from BTC-network based on X-BTC block height in ChainX network.
            let new_block = match self.bitcoin.block_by_height(new_height).await {
                Ok(block) => block,
                Err(_) => {
                    info!("[Service|run] Relay to the latest Block #{}", new_height);
                    info!("[Service|run] Waiting for next BTC Block...");
                    tokio::time::delay_for(Duration::from_secs(self.conf.btc_block_interval)).await;
                    continue;
                }
            };
            // Check if the current BTC block is a fork block.
            if self.is_fork_block(new_height, &new_block) {
                // example: next block #1863321, current block #1863320 is a fork block
                // rollback to the block #18663319 (current block = #18663319, next block = #18663320)
                self.blocks.remove(&self.current_height);
                self.current_height -= 1;
                warn!(
                    "[Service|is_fork_block] Rollback block to #{}",
                    self.current_height
                );
                new_height -= 1;
                continue;
            }
            self.blocks.insert(new_height, new_block);
            self.current_height = new_height;

            // ================================================================

            let confirmed_block = self.confirmed_block();
            let current_block = self.current_block();
            // Push BTC block header and confirmed transaction to the ChainX.
            if let Err(err) = self.push_xbtc_block(&current_block, &confirmed_block).await {
                error!("[Service|push_xbtc_block] error: {:?}", err);
                tokio::time::delay_for(Duration::from_secs(5)).await;
                return Err(err);
            }

            // Make sure btc header and transactions were submitted to the ChainX.
            let current_block_hash = current_block.hash();
            if let Some(header) = self.chainx.btc_block_header(&current_block_hash).await? {
                info!(
                    "[Service|run] BTC Block #{} ({:?}) was submitted successfully",
                    header.height,
                    hash_rev(header.header.hash()),
                );
                let new_confirmed_height = self.chainx.btc_confirmed_index().await?.height;
                self.update_confirmed_height(new_confirmed_height);
                new_height += 1;
            } else {
                warn!(
                    "[Service|run] BTC BlockHeaderInfo ({:?}) doesn't exist on ChainX",
                    hash_rev(current_block_hash)
                );
                self.blocks.remove(&self.current_height);
                self.current_height -= 1;
            }

            info!(
                "[Service|run] new_height: {}, BTC Blocks: {:?}",
                new_height,
                self.blocks
                    .iter()
                    .map(|(height, block)| (height, hash_rev(block.hash())))
                    .collect::<Vec<_>>()
            );
        }
    }

    /// Get the confirmed bitcoin block.
    fn confirmed_block(&self) -> &BtcBlock {
        self.blocks
            .get(&self.confirmed_height)
            .expect("Block with confirmed height must exist; qed")
    }

    /// Get the current bitcoin block.
    fn current_block(&self) -> &BtcBlock {
        self.blocks
            .get(&self.current_height)
            .expect("Block with current height must exist; qed")
    }

    /// Update the confirmed block height and remove the confirmed blocks from the blocks.
    fn update_confirmed_height(&mut self, new_confirmed_height: u32) {
        assert!(new_confirmed_height >= self.confirmed_height);
        assert!(new_confirmed_height <= self.current_height);
        // remove all blocks that the height < confirmed height
        for height in self.confirmed_height..new_confirmed_height {
            self.blocks.remove(&height);
        }
        self.confirmed_height = new_confirmed_height;
    }
}

impl Service {
    async fn check_and_send_btc_withdrawal_proposal(&self) -> Result<Option<H256>> {
        if let Some(withdrawal_proposal) = self.chainx.btc_withdrawal_proposal().await? {
            // Check whether the vote of the withdrawal proposal is finished
            if withdrawal_proposal.sig_state == VoteResult::Finish {
                let tx = serialize(&withdrawal_proposal.tx).take();
                let hex_tx = hex::encode(&tx);
                info!("[Bitcoin|send_raw_transaction] Btc Tx Hex: {}", hex_tx);
                match self.bitcoin.send_raw_transaction(hex_tx).await {
                    Ok(hash) => {
                        info!(
                            "[Bitcoin|send_raw_transaction] Transaction Hash: {:?}",
                            hash
                        );
                        return Ok(Some(hash));
                    }
                    Err(err) => {
                        // Transaction already in block chain
                        warn!("[Bitcoin|send_raw_transaction] Error: {:?}", err);
                    }
                }
            }
        }
        Ok(None)
    }

    // Check if the current BTC block is a fork block,
    // if it is, return the `true`, otherwise return `false`.
    fn is_fork_block(&self, new_height: u32, new_block: &BtcBlock) -> bool {
        // if `new_block_header.prev_header_hash != current_block_header_hash`,
        // then current block is a fork block, and we should rollback to the previous block of current block.
        //
        // example: new block #1863321, current block # 18663320 (is a fork block)
        // we should rollback to the block #18663319 to check if block #1863319 is a fork block too.
        if self.current_block().hash() != new_block.header().previous_header_hash {
            warn!(
                "[Service|is_fork_block] Current Block #{} ({:?}) is a fork block",
                self.current_height,
                hash_rev(self.current_block().hash()),
            );
            info!(
                "[Service|is_fork_block] New Block Hash #{} ({:?}), Previous Block Hash: {:?}",
                new_height,
                hash_rev(new_block.hash()),
                hash_rev(new_block.header().previous_header_hash)
            );
            return true;
        }
        false
    }

    /// Submit XBTC block header, XBTC deposit/withdraw transaction to the ChainX.
    pub async fn push_xbtc_block(
        &self,
        current_block: &BtcBlock,
        confirmed_block: &BtcBlock,
    ) -> Result<()> {
        // Check whether the current block header has already existed on the ChainX.
        let current_block_hash = current_block.hash();
        if let Some(block_header) = self.chainx.btc_block_header(&current_block_hash).await? {
            info!(
                "[Service|push_xbtc_block] Block Header #{} ({:?}) has been pushed to the ChainX network",
                block_header.height, hash_rev(current_block_hash)
            );
        } else {
            self.push_xbtc_header(current_block).await?;
        }

        // Check whether push header only.
        if self.conf.only_header {
            return Ok(());
        }

        self.push_xbtc_transaction(confirmed_block).await?;
        Ok(())
    }

    /// Submit XBTC block header to the ChainX.
    pub async fn push_xbtc_header(&self, block: &BtcBlock) -> Result<()> {
        info!(
            "[Service|push_xbtc_header] Block Hash: {:?}",
            hash_rev(block.hash())
        );
        self.chainx
            .push_btc_header(&self.signer, &block.header)
            .await?;
        Ok(())
    }

    /// Submit XBTC deposit/withdraw transaction to the ChainX.
    pub async fn push_xbtc_transaction(&self, confirmed_block: &BtcBlock) -> Result<()> {
        info!(
            "[Service|push_xbtc_transaction] Push Transactions Of Confirmed Block Hash: {:?}",
            hash_rev(confirmed_block.hash())
        );

        let mut needed = Vec::new();
        let mut tx_hashes = Vec::with_capacity(confirmed_block.transactions.len());
        let mut tx_matches = Vec::with_capacity(confirmed_block.transactions.len());
        let mut tx_xbridge = Vec::with_capacity(confirmed_block.transactions.len());

        let requests_infos = self.chainx.make_xbridge_requests_info().await?;

        for tx in &confirmed_block.transactions {
            // Prepare for constructing partial merkle tree
            tx_hashes.push(tx.hash());
            if tx.is_coinbase() {
                tx_matches.push(false);
                continue;
            }

            let outpoint = tx.inputs[0].previous_output;
            let prev_tx_hash = hex::encode(hash_rev(outpoint.txid));
            let prev_tx = self.bitcoin.raw_transaction(prev_tx_hash).await?;

            let request_type = self.chainx.btc_tx_detector.detect_xbridge_transaction(
                tx,
                &prev_tx,
                &requests_infos,
                OpReturnExtractor::extract_account,
            );

            tx_xbridge.push((
                request_type,
                {
                    let mut bytes = tx.hash().as_bytes().to_vec();
                    bytes.reverse();
                    hex::encode(bytes).as_bytes().to_vec()
                },
                serialize(tx).to_vec(),
            ));

            // Detect X-BTC transaction type
            // Withdrawal: must have a previous transaction
            // Deposit: don't require previous transaction generally,

            match self.chainx.btc_tx_detector.detect_transaction_type(
                tx,
                Some(&prev_tx),
                OpReturnExtractor::extract_account,
                self.chainx.current_trustee_pair,
                self.chainx.previous_trustee_pair,
            ) {
                BtcTxMetaType::Withdrawal => {
                    info!(
                        "X-BTC Withdrawal (PrevTx: {:?}, Tx: {:?})",
                        hash_rev(prev_tx.hash()),
                        hash_rev(tx.hash())
                    );
                    tx_matches.push(true);
                    needed.push((tx.clone(), Some(prev_tx)));
                }
                BtcTxMetaType::Deposit(BtcDepositInfo {
                    deposit_value,
                    op_return,
                    input_addr,
                }) => {
                    info!(
                        "X-BTC Deposit [{}] (Tx: {:?})",
                        deposit_value,
                        hash_rev(tx.hash())
                    );
                    tx_matches.push(true);
                    match (input_addr, op_return) {
                        (_, Some((account, _))) => {
                            if self.chainx.btc_pending_deposits(account).await?.is_empty() {
                                needed.push((tx.clone(), None));
                            } else {
                                needed.push((tx.clone(), Some(prev_tx)));
                            }
                        }
                        (Some(_), None) => needed.push((tx.clone(), Some(prev_tx))),
                        (None, None) => {
                            error!(
                                "[Service|push_xbtc_transaction] parsing prev_tx or op_return error, tx {:?}",
                                hash_rev(tx.hash())
                            );
                            needed.push((tx.clone(), Some(prev_tx)));
                        }
                    }
                }
                BtcTxMetaType::HotAndCold
                | BtcTxMetaType::TrusteeTransition
                | BtcTxMetaType::Irrelevance => tx_matches.push(false),
            }
        }

        let merkle_proof = PartialMerkleTree::from_txids(&tx_hashes, &tx_matches);

        if tx_xbridge.is_empty() {
            info!(
                "[Service|push_xbtc_transaction] No xbridge txs in Confirmed Block {:?}",
                hash_rev(confirmed_block.hash())
            );
        }

        for (request_type, tx_id, raw_tx) in tx_xbridge.into_iter() {
            match request_type {
                RequestType::Issue(id) => {
                    info!("[Service|xbridge] Sniffing Issue transaction {:?}", tx_id);
                    self.chainx
                        .client
                        .execute_issue_and_watch(
                            &self.signer,
                            id,
                            tx_id,
                            serialize(&merkle_proof).to_vec(),
                            raw_tx,
                        )
                        .await?;
                }
                RequestType::Redeem(id) => {
                    info!("[Service|xbridge] Sniffing Redeem transaction {:?}", tx_id);
                    self.chainx
                        .client
                        .execute_redeem_and_watch(
                            &self.signer,
                            id,
                            tx_id,
                            serialize(&merkle_proof).to_vec(),
                            raw_tx,
                        )
                        .await?;
                }
                _ => {}
            }
        }

        if !needed.is_empty() {
            info!(
                "[Service|push_xbtc_transaction] Generate partial merkle tree from the Confirmed Block {:?}",
                hash_rev(confirmed_block.hash())
            );

            // Construct partial merkle tree
            // We can never have zero txs in a merkle block, we always need the coinbase tx.

            // Push xbtc relay (withdraw/deposit) transaction
            for (tx, prev_tx) in needed {
                let relayed_info = BtcRelayedTxInfo {
                    block_hash: confirmed_block.hash(),
                    merkle_proof: merkle_proof.clone(),
                };

                if let Some(state) = self.chainx.btc_tx_state(&tx.hash()).await? {
                    if state.result == BtcTxResult::Success {
                        continue;
                    }
                }

                self.chainx
                    .push_btc_transaction(&self.signer, &tx, &relayed_info, &prev_tx)
                    .await?;
            }
        } else {
            info!(
                "[Service|push_xbtc_transaction] No X-BTC Deposit/Withdraw Transactions in th Confirmed Block {:?}",
                hash_rev(confirmed_block.hash())
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sp_core::crypto::DEV_ADDRESS;
    use sp_core::crypto::DEV_PHRASE;

    // use your own node config.
    const CHAINX_WS_URL: &str = "ws://localhost:8087";
    const BITCOIN_HTTP_URL: &str = "http://auth:bitcoin-b2dd077@115.29.163.193:18332";
    const TIMEOUT: u64 = 15;

    #[ignore]
    #[tokio::test]
    async fn test_push_btc_header() {
        let bitcoin = Bitcoin::new(BITCOIN_HTTP_URL, TIMEOUT);

        let chainx = ChainX::new(CHAINX_WS_URL, TIMEOUT).await.unwrap();
        let height = chainx.btc_best_index().await.unwrap().height;
        let block = bitcoin.block_by_height(height + 1).await.unwrap();

        let alice = ChainXPair::from_string(&format!("{}//Alice", DEV_PHRASE), None).unwrap();
        let signer = ChainXPairSigner::new(alice);
        chainx
            .push_btc_header(&signer, block.header())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_push_transaction() {
        // async_io::Async::<std::net::TcpStream>::connect("117.51.142.70:9097".to_socket_addrs().await.unwrap()).await.unwrap();
        // panic!();
        let conf = Config {
            btc_url: BITCOIN_HTTP_URL.parse().unwrap(),
            btc_block_interval: 120,
            chainx_url: CHAINX_WS_URL.parse().unwrap(),
            chainx_signer: format!("{}//Alice", DEV_PHRASE),
            only_header: true,
            log_path: std::path::Path::new("log/btc_relay.log").to_path_buf(),
            log_level: log::LevelFilter::Debug,
            log_roll_size: 100,
            log_roll_count: 5,
            rpc_timeout: 15,
        };
        crate::logger::init(&conf).unwrap();
        let service = Service::new(conf).await.unwrap();
        // let block = service.bitcoin.block_by_height(1_906_702).await.unwrap();
        let block = service.bitcoin.block_by_height(1_970_389).await.unwrap();
        service.push_xbtc_transaction(&block).await.unwrap();
    }
}
