//! Concurrent proof pipeline — queued proof generation with bounded workers.
//!
//! Accepts `ProofRequest`s via a bounded channel, dispatches them across a
//! configurable number of worker threads, and delivers results through
//! per-request oneshot channels.
//!
//! # Example
//!
//! ```ignore
//! let pipeline = ProofPipeline::start(config, transfer_handle, withdraw_handle);
//! let rx = pipeline.submit_transfer(job)?;
//! let proof_result = rx.recv().unwrap();
//! pipeline.shutdown();
//! ```

use std::sync::mpsc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::{self, JoinHandle};

use halo2_proofs::plonk;

use crate::{
    SharedProverHandle, SharedWithdrawProverHandle,
    TransferJob, WithdrawJob,
    TransferProof, WithdrawProof,
    prove_transfer, prove_withdraw,
};

/// Pipeline configuration.
#[derive(Clone, Debug)]
pub struct PipelineConfig {
    /// Maximum number of queued proof requests before `submit` blocks.
    pub queue_capacity: usize,
    /// Number of worker threads (defaults to available parallelism).
    pub num_workers: usize,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        let num_workers = thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(2);
        Self {
            queue_capacity: 64,
            num_workers,
        }
    }
}

/// The result type delivered for each completed proof.
pub type TransferResult = Result<TransferProof, plonk::Error>;
pub type WithdrawResult = Result<WithdrawProof, plonk::Error>;

/// A pending proof result receiver (non-blocking after proof is ready).
pub type TransferResultRx = mpsc::Receiver<TransferResult>;
pub type WithdrawResultRx = mpsc::Receiver<WithdrawResult>;

/// Internal message sent to worker threads.
enum ProofRequest {
    Transfer {
        job: TransferJob,
        reply: mpsc::SyncSender<TransferResult>,
    },
    Withdraw {
        job: WithdrawJob,
        reply: mpsc::SyncSender<WithdrawResult>,
    },
    Shutdown,
}

/// Error returned when the pipeline has been shut down.
#[derive(Debug)]
pub struct PipelineClosedError;

impl std::fmt::Display for PipelineClosedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "proof pipeline is closed")
    }
}

impl std::error::Error for PipelineClosedError {}

/// Pipeline statistics.
#[derive(Debug, Clone)]
pub struct PipelineStats {
    pub submitted: u64,
    pub completed: u64,
    pub failed: u64,
}

/// A concurrent proof generation pipeline.
///
/// Workers pull jobs from a shared bounded channel and generate proofs
/// using thread-safe prover handles.
pub struct ProofPipeline {
    tx: mpsc::SyncSender<ProofRequest>,
    workers: Vec<JoinHandle<()>>,
    submitted: AtomicU64,
    completed: std::sync::Arc<AtomicU64>,
    failed: std::sync::Arc<AtomicU64>,
}

impl ProofPipeline {
    /// Start the pipeline with the given configuration and prover handles.
    pub fn start(
        config: PipelineConfig,
        transfer_handle: SharedProverHandle,
        withdraw_handle: SharedWithdrawProverHandle,
    ) -> Self {
        let (tx, rx) = mpsc::sync_channel::<ProofRequest>(config.queue_capacity);
        // Wrap receiver in Arc<Mutex> so workers can share it.
        let rx = std::sync::Arc::new(std::sync::Mutex::new(rx));

        let completed_arc = std::sync::Arc::new(AtomicU64::new(0));
        let failed_arc = std::sync::Arc::new(AtomicU64::new(0));

        let mut workers = Vec::with_capacity(config.num_workers);

        for id in 0..config.num_workers {
            let rx = rx.clone();
            let th = transfer_handle.clone();
            let wh = withdraw_handle.clone();
            let completed_w = completed_arc.clone();
            let failed_w = failed_arc.clone();

            let handle = thread::Builder::new()
                .name(format!("prover-worker-{id}"))
                .spawn(move || {
                    loop {
                        let req = {
                            let guard = rx.lock().expect("rx mutex poisoned");
                            match guard.recv() {
                                Ok(req) => req,
                                Err(_) => return, // channel closed
                            }
                        };

                        match req {
                            ProofRequest::Transfer { mut job, reply } => {
                                let result = prove_transfer(&th, &job.inputs, &job.outputs, &mut job.tree, job.fee);
                                if result.is_ok() {
                                    completed_w.fetch_add(1, Ordering::Relaxed);
                                } else {
                                    failed_w.fetch_add(1, Ordering::Relaxed);
                                }
                                let _ = reply.send(result);
                            }
                            ProofRequest::Withdraw { mut job, reply } => {
                                let result = prove_withdraw(&wh, &job.inputs, &job.outputs, &mut job.tree, job.exit_value, job.fee);
                                if result.is_ok() {
                                    completed_w.fetch_add(1, Ordering::Relaxed);
                                } else {
                                    failed_w.fetch_add(1, Ordering::Relaxed);
                                }
                                let _ = reply.send(result);
                            }
                            ProofRequest::Shutdown => return,
                        }
                    }
                })
                .expect("failed to spawn prover worker");

            workers.push(handle);
        }

        Self {
            tx,
            workers,
            submitted: AtomicU64::new(0),
            completed: completed_arc,
            failed: failed_arc,
        }
    }

    /// Submit a transfer proof job. Returns a receiver for the result.
    pub fn submit_transfer(&self, job: TransferJob) -> Result<TransferResultRx, PipelineClosedError> {
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        self.tx
            .send(ProofRequest::Transfer { job, reply: reply_tx })
            .map_err(|_| PipelineClosedError)?;
        self.submitted.fetch_add(1, Ordering::Relaxed);
        Ok(reply_rx)
    }

    /// Submit a withdrawal proof job. Returns a receiver for the result.
    pub fn submit_withdraw(&self, job: WithdrawJob) -> Result<WithdrawResultRx, PipelineClosedError> {
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        self.tx
            .send(ProofRequest::Withdraw { job, reply: reply_tx })
            .map_err(|_| PipelineClosedError)?;
        self.submitted.fetch_add(1, Ordering::Relaxed);
        Ok(reply_rx)
    }

    /// Pipeline statistics snapshot.
    pub fn stats(&self) -> PipelineStats {
        PipelineStats {
            submitted: self.submitted.load(Ordering::Relaxed),
            completed: self.completed.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Relaxed),
        }
    }

    /// Number of active worker threads.
    pub fn num_workers(&self) -> usize {
        self.workers.len()
    }

    /// Gracefully shut down all workers (blocks until done).
    pub fn shutdown(self) {
        // Send one Shutdown per worker.
        for _ in &self.workers {
            let _ = self.tx.send(ProofRequest::Shutdown);
        }
        // Drop the sender to unblock any workers waiting on recv.
        drop(self.tx);
        for w in self.workers {
            let _ = w.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipeline_config_default() {
        let cfg = PipelineConfig::default();
        assert!(cfg.queue_capacity > 0);
        assert!(cfg.num_workers >= 1);
    }

    #[test]
    fn pipeline_closed_error_display() {
        let err = PipelineClosedError;
        assert_eq!(format!("{err}"), "proof pipeline is closed");
    }
}
