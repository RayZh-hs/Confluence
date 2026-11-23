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
        ports("HOP_TCP", "HOP_UDP", (16101, 16100))?,
        ports("FORWARD_TCP", "FORWARD_UDP", (18080, 18081))?,
        Some(TransitPeer {
            peer: peer("HOP_PUB")?,
            token: &secret("HOP_TOKEN_FILE")?,
        }),
    )?)
    .await
}
