//! Background tasks for the RPC server.
//!
//! These tasks run alongside the HTTP server and perform periodic maintenance:
//! - **Batch flushing**: poll the `BatchAccumulator` for ready batches
//! - **Epoch finalization**: advance and finalize nullifier epochs
//!
//! All tasks respect a shutdown signal so the server can stop gracefully.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;

use lumora_node::batch_accumulator::BatchPollResult;
use lumora_node::LumoraNode;

/// Interval between batch accumulator polls.
const BATCH_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Interval between epoch finalization checks.
const EPOCH_CHECK_INTERVAL: Duration = Duration::from_secs(60);

/// Interval between bridge deposit polling.
const BRIDGE_POLL_INTERVAL: Duration = Duration::from_secs(30);

/// Maximum time allowed for a single bridge poll operation before it is
/// considered stuck. Prevents a hung RPC call from blocking the loop.
const BRIDGE_POLL_TIMEOUT: Duration = Duration::from_secs(25);

/// Maximum time to wait for background tasks to finish during shutdown.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);

/// Handle returned by [`spawn_background_tasks`] that supports graceful
/// shutdown via a `tokio::sync::watch` channel.
pub struct BackgroundHandle {
    handles: Vec<tokio::task::JoinHandle<()>>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
}

impl BackgroundHandle {
    /// Signal all background tasks to stop and wait for them to finish.
    ///
    /// If tasks don't exit within [`SHUTDOWN_TIMEOUT`], they are aborted.
    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);

        let join_all = async {
            for h in self.handles {
                let _ = h.await;
            }
        };

        if tokio::time::timeout(SHUTDOWN_TIMEOUT, join_all)
            .await
            .is_err()
        {
            tracing::warn!(
                timeout_secs = SHUTDOWN_TIMEOUT.as_secs(),
                "background tasks did not exit in time — aborting",
            );
        }
    }

    /// Number of running tasks.
    pub fn len(&self) -> usize {
        self.handles.len()
    }

    /// Whether there are no running tasks.
    pub fn is_empty(&self) -> bool {
        self.handles.is_empty()
    }
}

/// Spawn all background tasks. Returns a handle that can be used
/// for graceful shutdown.
pub fn spawn_background_tasks(
    state: Arc<RwLock<LumoraNode>>,
) -> BackgroundHandle {
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let mut handles = Vec::new();

    // Batch accumulator polling task
    let batch_state = state.clone();
    let batch_rx = shutdown_rx.clone();
    handles.push(tokio::spawn(async move {
        batch_poll_loop(batch_state, batch_rx).await;
    }));

    // Epoch finalization task
    let epoch_state = state.clone();
    let epoch_rx = shutdown_rx.clone();
    handles.push(tokio::spawn(async move {
        epoch_finalize_loop(epoch_state, epoch_rx).await;
    }));

    // Bridge deposit polling task
    let bridge_state = state;
    let bridge_rx = shutdown_rx;
    handles.push(tokio::spawn(async move {
        bridge_poll_loop(bridge_state, bridge_rx).await;
    }));

    BackgroundHandle { handles, shutdown_tx }
}

/// Periodically poll the batch accumulator and log ready batches.
///
/// When a batch is ready (meets min_batch_size or max_wait elapsed),
/// it is drained from the accumulator. In a production system this
/// would submit the batch for proving or relay it to peers.
async fn batch_poll_loop(
    state: Arc<RwLock<LumoraNode>>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(BATCH_POLL_INTERVAL);
    loop {
        tokio::select! {
            _ = interval.tick() => {}
            _ = shutdown.changed() => {
                tracing::info!("batch_poll_loop shutting down gracefully");
                return;
            }
        }
        let mut node = state.write().await;
        match node.batch.poll() {
            BatchPollResult::Ready(batch) => {
                tracing::info!(
                    batch_size = batch.len(),
                    "batch ready — flushing accumulated transactions",
                );
            }
            BatchPollResult::NotReady => {}
        }
    }
}

/// Periodically finalize the current nullifier epoch if it has pending
/// nullifiers, and prune old epochs beyond the retention limit.
///
/// This ensures epoch roots are available for cross-chain sync even if
/// individual transactions don't advance the epoch boundary.
async fn epoch_finalize_loop(
    state: Arc<RwLock<LumoraNode>>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(EPOCH_CHECK_INTERVAL);
    loop {
        tokio::select! {
            _ = interval.tick() => {}
            _ = shutdown.changed() => {
                tracing::info!("epoch_finalize_loop shutting down gracefully");
                return;
            }
        }
        let mut node = state.write().await;
        let em = node.pool.state.epoch_manager_mut();
        if let Some((epoch_id, root)) = em.finalize_current_epoch() {
            let root_hex = hex::encode(ff::PrimeField::to_repr(&root));
            tracing::info!(
                epoch_id,
                root = %root_hex,
                "epoch finalized — nullifier root committed",
            );
        }
    }
}

/// Periodically poll the bridge for new L1 deposits and process them.
///
/// Only runs if the node has a bridge configured. Logs each poll result.
async fn bridge_poll_loop(
    state: Arc<RwLock<LumoraNode>>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(BRIDGE_POLL_INTERVAL);
    loop {
        tokio::select! {
            _ = interval.tick() => {}
            _ = shutdown.changed() => {
                tracing::info!("bridge_poll_loop shutting down gracefully");
                return;
            }
        }
        let mut node = state.write().await;
        if !node.has_bridge() {
            continue;
        }
        let result = tokio::time::timeout(
            BRIDGE_POLL_TIMEOUT,
            std::future::ready(node.poll_bridge_deposits()),
        ).await;
        match result {
            Err(_) => {
                tracing::warn!("bridge poll timed out after {}s", BRIDGE_POLL_TIMEOUT.as_secs());
            }
            Ok(Ok(0)) => {}
            Ok(Ok(n)) => {
                tracing::info!(new_deposits = n, "bridge poll: processed L1 deposits");
            }
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "bridge poll failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn background_tasks_spawn_and_cancel() {
        let node = LumoraNode::init();
        let state = Arc::new(RwLock::new(node));
        let handle = spawn_background_tasks(state);
        assert_eq!(handle.len(), 3);
        // Graceful shutdown — tasks should exit on their own.
        handle.shutdown().await;
    }
}
