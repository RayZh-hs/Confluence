use confluence_examples::{ExampleResult, direct, identity, peer, ports, run, secret};

#[tokio::main]
async fn main() -> ExampleResult {
    run(direct::alice(
        identity()?,
        peer("BOB_PUB")?,
        &secret("ENDPOINT_TOKEN_FILE")?,
        ports("BOB_TCP", "BOB_UDP", (14101, 14100))?,
        ports("FORWARD_TCP", "FORWARD_UDP", (18080, 18081))?,
    )?)
    .await
}
