use confluence_examples::{ExampleResult, direct, identity, peer, ports, run, secret};

#[tokio::main]
async fn main() -> ExampleResult {
    run(direct::bob(
        identity()?,
        peer("ALICE_PUB")?,
        &secret("ENDPOINT_TOKEN_FILE")?,
        ports("BACKEND_TCP", "BACKEND_UDP", (8080, 8081))?,
        ports("BOB_TCP", "BOB_UDP", (14101, 14100))?,
    )?)
    .await
}
