use crate::mock::{RAW_TX0, RAW_TX0_PREV_TX, RAW_TX1};
use crate::runtime::frame::xgateway_bitcoin_v2::ExecuteIssueCallExt;
use crate::ChainX;
use light_bitcoin::{
    chain::Transaction as BtcTransaction,
    primitives::{h256_rev, H256},
    serialization::serialize,
};
use xp_gateway_bitcoin::{AccountExtractor, OpReturnExtractor};

#[tokio::test]
async fn test_filter_transaction() {
    let chainx = ChainX::new("ws://127.0.0.1:8087", 15u64).await.unwrap();
    let tx = RAW_TX1.parse::<BtcTransaction>().unwrap();
    let prev_tx = RAW_TX0_PREV_TX.parse::<BtcTransaction>().unwrap();
    let (input, output, op_return, amount) =
        chainx
            .btc_tx_detector
            .parse_transaction(&tx, None, OpReturnExtractor::extract_account);

    // assert_eq!(hex::encode(serialize(&tx)), RAW_TX0);
    //
    // let mut bytes = tx.hash().as_bytes().to_owned();
    // bytes.reverse();
    // assert_eq!(
    //     hex::encode(bytes),
    //     "34e46091d5ec48a10c2eb98b710455e1c7e8b7baf1cb7d1a98de5cc123035e9d"
    // );

    println!("Input is {:?}", input);
    println!("Output is {}", &output.unwrap());
    println!("op_return is {:?}", op_return);
    println!("amount is {}", amount);

    let requests_infos = chainx.make_xbridge_requests_info().await.unwrap();

    let request_type = chainx.btc_tx_detector.detect_xbridge_transaction(
        &tx,
        &prev_tx,
        &requests_infos,
        OpReturnExtractor::extract_account,
    );

    println!("{:?}", request_type);
}
