//! Transaction mempool — holds pending transactions before execution.
//!
//! Transactions are queued and can be drained in order for batch execution.
//! The mempool enforces a maximum size to prevent unbounded growth.

use lumora_contracts::{DepositRequest, TransferRequest, WithdrawRequest};

/// Maximum number of pending transactions in the mempool.
pub const MAX_MEMPOOL_SIZE: usize = 1024;

/// A pending transaction in the mempool.
#[derive(Debug)]
pub enum PendingTx {
    Deposit(DepositRequest),
    Transfer(TransferRequest),
    Withdraw(WithdrawRequest),
}

/// A bounded FIFO queue of pending transactions.
#[derive(Debug)]
pub struct Mempool {
    txs: Vec<PendingTx>,
    max_size: usize,
}

impl Mempool {
    /// Create a new mempool with the default capacity.
    pub fn new() -> Self {
        Self {
            txs: Vec::new(),
            max_size: MAX_MEMPOOL_SIZE,
        }
    }

    /// Create a mempool with a custom maximum size.
    pub fn with_capacity(max_size: usize) -> Self {
        Self {
            txs: Vec::new(),
            max_size,
        }
    }

    /// Submit a transaction to the mempool.
    ///
    /// Returns `false` if the mempool is full.
    pub fn submit(&mut self, tx: PendingTx) -> bool {
        if self.txs.len() >= self.max_size {
            return false;
        }
        self.txs.push(tx);
        true
    }

    /// Number of pending transactions.
    pub fn len(&self) -> usize {
        self.txs.len()
    }

    /// Whether the mempool is empty.
    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }

    /// Drain all pending transactions for batch execution.
    pub fn drain_all(&mut self) -> Vec<PendingTx> {
        std::mem::take(&mut self.txs)
    }

    /// Take up to `n` transactions from the front.
    pub fn take(&mut self, n: usize) -> Vec<PendingTx> {
        let split = n.min(self.txs.len());
        let rest = self.txs.split_off(split);
        std::mem::replace(&mut self.txs, rest)
    }

    /// Peek at the next pending transaction without removing it.
    pub fn peek(&self) -> Option<&PendingTx> {
        self.txs.first()
    }

    /// Clear all pending transactions.
    pub fn clear(&mut self) {
        self.txs.clear();
    }
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pasta_curves::pallas;

    fn dummy_deposit() -> PendingTx {
        PendingTx::Deposit(DepositRequest {
            commitment: pallas::Base::from(42u64),
            amount: 100,
        })
    }

    #[test]
    fn submit_and_drain() {
        let mut pool = Mempool::new();
        assert!(pool.is_empty());
        assert!(pool.submit(dummy_deposit()));
        assert!(pool.submit(dummy_deposit()));
        assert_eq!(pool.len(), 2);

        let txs = pool.drain_all();
        assert_eq!(txs.len(), 2);
        assert!(pool.is_empty());
    }

    #[test]
    fn bounded_capacity() {
        let mut pool = Mempool::with_capacity(2);
        assert!(pool.submit(dummy_deposit()));
        assert!(pool.submit(dummy_deposit()));
        assert!(!pool.submit(dummy_deposit())); // full
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn take_partial() {
        let mut pool = Mempool::new();
        for _ in 0..5 {
            pool.submit(dummy_deposit());
        }
        let batch = pool.take(3);
        assert_eq!(batch.len(), 3);
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn peek_without_remove() {
        let mut pool = Mempool::new();
        assert!(pool.peek().is_none());
        pool.submit(dummy_deposit());
        assert!(pool.peek().is_some());
        assert_eq!(pool.len(), 1); // not removed
    }
}
