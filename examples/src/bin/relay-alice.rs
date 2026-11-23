use confluence_examples::{
    ExampleResult, identity, peer, ports,
    relayed::{self, TransitPeer},
    run, secret,
};

#[tokio::main]
async fn main() -> ExampleResult {
    run(relayed::alice(
        identity()?,
        peer("BOB_PUB")?,
        &secret("ENDPOINT_TOKEN_FILE")?,
        TransitPeer {
            peer: peer("RELAY_PUB")?,
            token: &secret("RELAY_ACCESS_TOKEN_FILE")?,
        },
        ports("RELAY_TCP", "RELAY_UDP", (16201, 16200))?,
        ports("FORWARD_TCP", "FORWARD_UDP", (18080, 18081))?,
        None,
    )?)
    .await
}
