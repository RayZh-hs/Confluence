use confluence_examples::{ExampleResult, identity, peer, ports, relayed, run, secret};

#[tokio::main]
async fn main() -> ExampleResult {
    run(relayed::relay(
        identity()?,
        peer("ALICE_PUB")?,
        peer("BOB_PUB")?,
        &secret("RELAY_ACCESS_TOKEN_FILE")?,
        &secret("RELAY_REG_TOKEN_FILE")?,
        ports("RELAY_TCP", "RELAY_UDP", (16201, 16200))?,
    )?)
    .await
}
