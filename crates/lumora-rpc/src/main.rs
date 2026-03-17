//! Binary entrypoint for the Lumora RPC server.

use std::io::{Error, ErrorKind};

use lumora_bitvm::adapters::emv::{EmvBridge, EmvConfig};
use lumora_node::LumoraNode;
use lumora_rpc::server;

const BRIDGE_TYPE_ENV: &str = "LUMORA_BRIDGE_TYPE";
const EMV_RPC_URL_ENV: &str = "EMV_RPC_URL";
const EMV_NETWORK_ID_ENV: &str = "EMV_NETWORK_ID";
const EMV_MERCHANT_ID_ENV: &str = "EMV_MERCHANT_ID";
const EMV_CURRENCY_ENV: &str = "EMV_CURRENCY";
const EMV_MIN_FINALITY_ENV: &str = "EMV_MIN_FINALITY";

fn apply_emv_bridge_from_env(node: &mut LumoraNode) -> std::io::Result<()> {
    let bridge_type = std::env::var(BRIDGE_TYPE_ENV).unwrap_or_else(|_| "none".to_string());

    if bridge_type.eq_ignore_ascii_case("none") || bridge_type.eq_ignore_ascii_case("local") {
        tracing::info!(bridge_type, "No host-chain bridge configured");
        return Ok(());
    }

    if !bridge_type.eq_ignore_ascii_case("emv") {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!(
                "unsupported bridge type '{}'; expected 'emv', 'local', or 'none'",
                bridge_type
            ),
        ));
    }

    let mut cfg = EmvConfig::default();

    if let Ok(v) = std::env::var(EMV_RPC_URL_ENV) {
        if !v.trim().is_empty() {
            cfg.rpc_url = v;
        }
    }
    if let Ok(v) = std::env::var(EMV_NETWORK_ID_ENV) {
        if !v.trim().is_empty() {
            cfg.network_id = v;
        }
    }
    if let Ok(v) = std::env::var(EMV_MERCHANT_ID_ENV) {
        if !v.trim().is_empty() {
            cfg.merchant_id = v;
        }
    }
    if let Ok(v) = std::env::var(EMV_CURRENCY_ENV) {
        if !v.trim().is_empty() {
            cfg.currency = v;
        }
    }
    if let Ok(v) = std::env::var(EMV_MIN_FINALITY_ENV) {
        if !v.trim().is_empty() {
            cfg.min_finality = v.parse::<u64>().map_err(|e| {
                Error::new(
                    ErrorKind::InvalidInput,
                    format!("invalid {EMV_MIN_FINALITY_ENV} '{v}': {e}"),
                )
            })?;
        }
    }

    if cfg.network_id.trim().is_empty()
        || cfg.merchant_id.trim().is_empty()
        || cfg.currency.trim().is_empty()
    {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "invalid EMV bridge config: network_id, merchant_id, and currency must be non-empty",
        ));
    }

    node.set_bridge(Box::new(EmvBridge::new(cfg.clone())));
    tracing::info!(
        rpc_url = %cfg.rpc_url,
        network_id = %cfg.network_id,
        merchant_id = %cfg.merchant_id,
        currency = %cfg.currency,
        min_finality = cfg.min_finality,
        "Configured EMV bridge"
    );

    Ok(())
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt::init();

    let addr = std::env::var("LUMORA_RPC_ADDR")
        .unwrap_or_else(|_| server::DEFAULT_ADDR.to_string());

    tracing::info!("Initialising Lumora node (generating proving keys)...");
    let mut node = LumoraNode::init();
    apply_emv_bridge_from_env(&mut node)?;
    tracing::info!("Node ready. Starting RPC server...");

    server::serve(node, &addr).await
}
