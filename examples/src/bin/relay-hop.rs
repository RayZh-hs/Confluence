use confluence_examples::{ExampleResult, identity, peer, ports, relayed, run, secret};

#[tokio::main]
async fn main() -> ExampleResult {
    run(relayed::hop(
        identity()?,
        peer("ALICE_PUB")?,
        &secret("HOP_TOKEN_FILE")?,
        ports("HOP_TCP", "HOP_UDP", (16101, 16100))?,
        ports("RELAY_TCP", "RELAY_UDP", (16201, 16200))?,
    )?)
    .await
}
