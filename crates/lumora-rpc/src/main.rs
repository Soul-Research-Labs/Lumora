//! Binary entrypoint for the Lumora RPC server.

use lumora_node::LumoraNode;
use lumora_rpc::server;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt::init();

    let addr = std::env::var("LUMORA_RPC_ADDR")
        .unwrap_or_else(|_| server::DEFAULT_ADDR.to_string());

    tracing::info!("Initialising Lumora node (generating proving keys)...");
    let node = LumoraNode::init();
    tracing::info!("Node ready. Starting RPC server...");

    server::serve(node, &addr).await
}
