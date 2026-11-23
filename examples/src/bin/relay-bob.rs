use confluence_examples::{ExampleResult, identity, peer, ports, relayed, run, secret};

#[tokio::main]
async fn main() -> ExampleResult {
    run(relayed::bob(
        identity()?,
        peer("ALICE_PUB")?,
        &secret("ENDPOINT_TOKEN_FILE")?,
        ports("BACKEND_TCP", "BACKEND_UDP", (8080, 8081))?,
        peer("RELAY_PUB")?,
        ports("RELAY_TCP", "RELAY_UDP", (16201, 16200))?,
        &secret("RELAY_REG_TOKEN_FILE")?,
    )?)
    .await
}
