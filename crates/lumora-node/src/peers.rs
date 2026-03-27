//! Peer registry — tracks known peers for state sync and note relay.
//!
//! This is a simple static peer list. Future versions may support
//! dynamic discovery (DNS seeds, DHT, gossip).

use std::collections::HashMap;
use std::time::Instant;

use serde::{Deserialize, Serialize};

/// Information about a known peer.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// The peer's RPC endpoint (e.g. "http://127.0.0.1:3030").
    pub addr: String,
    /// Last time we successfully contacted this peer.
    pub last_seen: Option<Instant>,
    /// Whether the peer is considered healthy.
    pub healthy: bool,
    /// Number of consecutive failures.
    pub failures: u32,
}

/// Serializable peer address for config files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerAddr {
    pub addr: String,
}

/// Maximum consecutive failures before marking a peer unhealthy.
const MAX_FAILURES: u32 = 3;

/// Default heartbeat interval in seconds.
pub const DEFAULT_HEARTBEAT_INTERVAL_SECS: u64 = 30;

/// Default timeout for a single heartbeat check in seconds.
pub const HEARTBEAT_TIMEOUT_SECS: u64 = 5;

/// Heartbeat configuration.
#[derive(Debug, Clone)]
pub struct HeartbeatConfig {
    /// How often to check peers (seconds).
    pub interval_secs: u64,
    /// Timeout per peer check (seconds).
    pub timeout_secs: u64,
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        Self {
            interval_secs: DEFAULT_HEARTBEAT_INTERVAL_SECS,
            timeout_secs: HEARTBEAT_TIMEOUT_SECS,
        }
    }
}

/// Registry of known peers.
#[derive(Debug)]
pub struct PeerRegistry {
    peers: HashMap<String, PeerInfo>,
}

impl PeerRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
        }
    }

    /// Create a registry from a list of seed addresses.
    pub fn from_seeds(seeds: &[String]) -> Self {
        let mut reg = Self::new();
        for addr in seeds {
            reg.add_peer(addr.clone());
        }
        reg
    }

    /// Add a peer to the registry.
    pub fn add_peer(&mut self, addr: String) {
        self.peers.entry(addr.clone()).or_insert(PeerInfo {
            addr,
            last_seen: None,
            healthy: true,
            failures: 0,
        });
    }

    /// Remove a peer from the registry.
    pub fn remove_peer(&mut self, addr: &str) {
        self.peers.remove(addr);
    }

    /// Mark a peer as successfully contacted.
    pub fn mark_success(&mut self, addr: &str) {
        if let Some(peer) = self.peers.get_mut(addr) {
            peer.last_seen = Some(Instant::now());
            peer.healthy = true;
            peer.failures = 0;
        }
    }

    /// Record a failed contact attempt.
    pub fn mark_failure(&mut self, addr: &str) {
        if let Some(peer) = self.peers.get_mut(addr) {
            peer.failures += 1;
            if peer.failures >= MAX_FAILURES {
                peer.healthy = false;
            }
        }
    }

    /// Get all healthy peers.
    pub fn healthy_peers(&self) -> Vec<&PeerInfo> {
        self.peers.values().filter(|p| p.healthy).collect()
    }

    /// Get all peers (including unhealthy).
    pub fn all_peers(&self) -> Vec<&PeerInfo> {
        self.peers.values().collect()
    }

    /// Number of known peers.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Load peer list from a JSON file.
    pub fn load(path: &std::path::Path) -> std::io::Result<Self> {
        let json = std::fs::read_to_string(path)?;
        let addrs: Vec<PeerAddr> = serde_json::from_str(&json)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let seeds: Vec<String> = addrs.into_iter().map(|p| p.addr).collect();
        Ok(Self::from_seeds(&seeds))
    }

    /// Save peer list to a JSON file.
    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        let addrs: Vec<PeerAddr> = self
            .peers
            .values()
            .map(|p| PeerAddr { addr: p.addr.clone() })
            .collect();
        let json = serde_json::to_string_pretty(&addrs)
            .map_err(std::io::Error::other)?;
        std::fs::write(path, json)
    }

    /// Get addresses of peers that are due for a heartbeat check.
    ///
    /// A peer is due if it has never been contacted, or if `interval` has
    /// elapsed since its last successful contact.
    pub fn peers_due_for_heartbeat(
        &self,
        interval: std::time::Duration,
    ) -> Vec<String> {
        let now = Instant::now();
        self.peers
            .values()
            .filter(|p| match p.last_seen {
                None => true,
                Some(t) => now.duration_since(t) >= interval,
            })
            .map(|p| p.addr.clone())
            .collect()
    }

    /// Summary of peer health for monitoring.
    pub fn health_summary(&self) -> PeerHealthSummary {
        let total = self.peers.len();
        let healthy = self.peers.values().filter(|p| p.healthy).count();
        let stale = self.peers.values().filter(|p| {
            p.last_seen.is_none_or(|t| {
                Instant::now().duration_since(t) > std::time::Duration::from_secs(120)
            })
        }).count();
        PeerHealthSummary { total, healthy, unhealthy: total - healthy, stale }
    }
}

/// Summary of peer registry health.
#[derive(Debug, Clone)]
pub struct PeerHealthSummary {
    pub total: usize,
    pub healthy: usize,
    pub unhealthy: usize,
    /// Peers not contacted in over 2 minutes.
    pub stale: usize,
}

// ---------------------------------------------------------------------------
// Byzantine fault detection
// ---------------------------------------------------------------------------

/// A state claim received from a peer at a specific height.
#[derive(Debug, Clone)]
pub struct StateClaim {
    /// The peer that made this claim.
    pub peer: String,
    /// Tree height (commitment count) at time of claim.
    pub height: u64,
    /// Merkle root claimed at that height.
    pub root: [u8; 32],
    /// When the claim was recorded.
    pub received_at: Instant,
}

/// Classification of a detected Byzantine fault.
#[derive(Debug, Clone)]
pub enum ByzantineFault {
    /// Peer claimed two different roots at the same height (equivocation).
    Equivocation {
        peer: String,
        height: u64,
        root_a: [u8; 32],
        root_b: [u8; 32],
    },
    /// Peer claimed a root at a height that conflicts with the local state.
    RootMismatch {
        peer: String,
        height: u64,
        claimed_root: [u8; 32],
        local_root: [u8; 32],
    },
    /// Peer HMAC verification failed (tampered or forged message).
    AuthFailure {
        peer: String,
    },
}

impl std::fmt::Display for ByzantineFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ByzantineFault::Equivocation { peer, height, .. } => {
                write!(f, "equivocation by {} at height {}", peer, height)
            }
            ByzantineFault::RootMismatch { peer, height, .. } => {
                write!(f, "root mismatch from {} at height {}", peer, height)
            }
            ByzantineFault::AuthFailure { peer } => {
                write!(f, "authentication failure from {}", peer)
            }
        }
    }
}

/// Tracks state claims from peers and detects Byzantine behaviour.
///
/// Keeps a bounded sliding window of recent claims per peer to detect
/// equivocation (same height, different root). Peers that accumulate
/// faults beyond `QUARANTINE_FAULT_THRESHOLD` are automatically
/// quarantined and excluded from sync.
#[derive(Debug)]
pub struct ByzantineDetector {
    /// Per-peer claims: peer_addr → (height → root).
    claims: HashMap<String, HashMap<u64, [u8; 32]>>,
    /// Detected faults (append-only log).
    faults: Vec<ByzantineFault>,
    /// Maximum number of height entries to keep per peer.
    max_history: usize,
    /// Peers quarantined due to accumulated faults.
    quarantined: std::collections::HashSet<String>,
    /// Permanent set of peers ever detected as equivocators.
    /// This set survives history eviction and persists across the session.
    known_equivocators: std::collections::HashSet<String>,
    /// Number of faults before a peer is quarantined.
    quarantine_threshold: usize,
}

/// Default per-peer history limit.
const DEFAULT_MAX_CLAIM_HISTORY: usize = 256;

/// Default number of faults before a peer is quarantined.
pub const QUARANTINE_FAULT_THRESHOLD: usize = 3;

impl Default for ByzantineDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ByzantineDetector {
    /// Create a new detector with the default history limit.
    pub fn new() -> Self {
        Self {
            claims: HashMap::new(),
            faults: Vec::new(),
            max_history: DEFAULT_MAX_CLAIM_HISTORY,
            quarantined: std::collections::HashSet::new(),
            known_equivocators: std::collections::HashSet::new(),
            quarantine_threshold: QUARANTINE_FAULT_THRESHOLD,
        }
    }

    /// Record a state claim from a peer. Returns a fault if equivocation is detected.
    ///
    /// If this fault causes the peer's total to reach the quarantine threshold,
    /// the peer is automatically quarantined.
    pub fn record_claim(
        &mut self,
        peer: &str,
        height: u64,
        root: [u8; 32],
    ) -> Option<ByzantineFault> {
        let peer_claims = self
            .claims
            .entry(peer.to_string())
            .or_default();

        if let Some(existing_root) = peer_claims.get(&height) {
            if *existing_root != root {
                let fault = ByzantineFault::Equivocation {
                    peer: peer.to_string(),
                    height,
                    root_a: *existing_root,
                    root_b: root,
                };
                self.faults.push(fault.clone());
                self.known_equivocators.insert(peer.to_string());
                self.maybe_quarantine(peer);
                return Some(fault);
            }
        } else {
            // Trim oldest entries if over limit.
            if peer_claims.len() >= self.max_history {
                if let Some(&min_height) = peer_claims.keys().min() {
                    peer_claims.remove(&min_height);
                }
            }
            peer_claims.insert(height, root);
        }
        None
    }

    /// Check a peer's claimed root against the local root at the same height.
    pub fn check_against_local(
        &mut self,
        peer: &str,
        height: u64,
        claimed_root: [u8; 32],
        local_root: [u8; 32],
    ) -> Option<ByzantineFault> {
        if claimed_root != local_root {
            let fault = ByzantineFault::RootMismatch {
                peer: peer.to_string(),
                height,
                claimed_root,
                local_root,
            };
            self.faults.push(fault.clone());
            self.maybe_quarantine(peer);
            Some(fault)
        } else {
            None
        }
    }

    /// Record an authentication failure from a peer.
    pub fn record_auth_failure(&mut self, peer: &str) {
        self.faults.push(ByzantineFault::AuthFailure {
            peer: peer.to_string(),
        });
        self.maybe_quarantine(peer);
    }

    /// Returns `true` if the peer has been quarantined.
    pub fn is_quarantined(&self, peer: &str) -> bool {
        self.quarantined.contains(peer)
    }

    /// Check if a peer has ever been detected as an equivocator.
    /// This persists even after the detailed claim history is evicted.
    pub fn is_known_equivocator(&self, peer: &str) -> bool {
        self.known_equivocators.contains(peer)
    }

    /// Returns the set of all quarantined peer addresses.
    pub fn quarantined_peers(&self) -> &std::collections::HashSet<String> {
        &self.quarantined
    }

    /// Remove a peer from quarantine (e.g. after manual review).
    pub fn lift_quarantine(&mut self, peer: &str) {
        self.quarantined.remove(peer);
    }

    /// Quarantine a peer if its total fault count reaches the threshold.
    fn maybe_quarantine(&mut self, peer: &str) {
        let count = self.faults.iter().filter(|f| match f {
            ByzantineFault::Equivocation { peer: p, .. }
            | ByzantineFault::RootMismatch { peer: p, .. }
            | ByzantineFault::AuthFailure { peer: p } => p == peer,
        }).count();
        if count >= self.quarantine_threshold {
            self.quarantined.insert(peer.to_string());
        }
    }

    /// All detected faults.
    pub fn faults(&self) -> &[ByzantineFault] {
        &self.faults
    }

    /// Number of faults detected.
    pub fn fault_count(&self) -> usize {
        self.faults.len()
    }

    /// Faults for a specific peer.
    pub fn faults_for_peer(&self, peer: &str) -> Vec<&ByzantineFault> {
        self.faults.iter().filter(|f| match f {
            ByzantineFault::Equivocation { peer: p, .. }
            | ByzantineFault::RootMismatch { peer: p, .. }
            | ByzantineFault::AuthFailure { peer: p } => p == peer,
        }).collect()
    }

    /// Clear all claims, fault history, and quarantine state.
    pub fn clear(&mut self) {
        self.claims.clear();
        self.faults.clear();
        self.quarantined.clear();
    }
}

impl Default for PeerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_and_query_peers() {
        let mut reg = PeerRegistry::new();
        assert!(reg.is_empty());

        reg.add_peer("http://localhost:3030".into());
        reg.add_peer("http://localhost:3031".into());
        assert_eq!(reg.len(), 2);
        assert_eq!(reg.healthy_peers().len(), 2);
    }

    #[test]
    fn failure_marks_unhealthy() {
        let mut reg = PeerRegistry::new();
        reg.add_peer("http://localhost:3030".into());

        reg.mark_failure("http://localhost:3030");
        reg.mark_failure("http://localhost:3030");
        assert_eq!(reg.healthy_peers().len(), 1); // still healthy (2 < 3)

        reg.mark_failure("http://localhost:3030");
        assert_eq!(reg.healthy_peers().len(), 0); // now unhealthy

        reg.mark_success("http://localhost:3030");
        assert_eq!(reg.healthy_peers().len(), 1); // recovered
    }

    #[test]
    fn from_seeds() {
        let seeds = vec!["http://a:1".into(), "http://b:2".into()];
        let reg = PeerRegistry::from_seeds(&seeds);
        assert_eq!(reg.len(), 2);
    }

    #[test]
    fn save_load_roundtrip() {
        let mut reg = PeerRegistry::new();
        reg.add_peer("http://localhost:3030".into());
        reg.add_peer("http://localhost:3031".into());

        let dir = std::env::temp_dir().join("lumora_test_peers");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("peers.json");

        reg.save(&path).expect("save");
        let loaded = PeerRegistry::load(&path).expect("load");
        assert_eq!(loaded.len(), 2);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    // ── Byzantine detection tests ───────────────────────────────────

    #[test]
    fn byzantine_equivocation_detected() {
        let mut det = ByzantineDetector::new();
        let root_a = [0xAAu8; 32];
        let root_b = [0xBBu8; 32];

        // First claim at height 10 — no fault.
        assert!(det.record_claim("peer1", 10, root_a).is_none());
        // Same peer, same height, different root → equivocation.
        let fault = det.record_claim("peer1", 10, root_b);
        assert!(fault.is_some());
        assert!(matches!(fault.unwrap(), ByzantineFault::Equivocation { .. }));
        assert_eq!(det.fault_count(), 1);
    }

    #[test]
    fn byzantine_same_claim_no_fault() {
        let mut det = ByzantineDetector::new();
        let root = [0xCCu8; 32];
        assert!(det.record_claim("peer1", 5, root).is_none());
        // Same peer, same height, same root — no fault.
        assert!(det.record_claim("peer1", 5, root).is_none());
        assert_eq!(det.fault_count(), 0);
    }

    #[test]
    fn byzantine_root_mismatch() {
        let mut det = ByzantineDetector::new();
        let claimed = [0x11u8; 32];
        let local = [0x22u8; 32];
        let fault = det.check_against_local("peer2", 42, claimed, local);
        assert!(fault.is_some());
        assert!(matches!(fault.unwrap(), ByzantineFault::RootMismatch { .. }));
    }

    #[test]
    fn byzantine_root_match_no_fault() {
        let mut det = ByzantineDetector::new();
        let root = [0x33u8; 32];
        assert!(det.check_against_local("peer3", 7, root, root).is_none());
        assert_eq!(det.fault_count(), 0);
    }

    #[test]
    fn byzantine_auth_failure() {
        let mut det = ByzantineDetector::new();
        det.record_auth_failure("peer4");
        assert_eq!(det.fault_count(), 1);
        assert!(matches!(det.faults()[0], ByzantineFault::AuthFailure { .. }));
    }

    #[test]
    fn byzantine_faults_for_peer() {
        let mut det = ByzantineDetector::new();
        det.record_auth_failure("peer_a");
        det.record_auth_failure("peer_b");
        det.record_auth_failure("peer_a");
        assert_eq!(det.faults_for_peer("peer_a").len(), 2);
        assert_eq!(det.faults_for_peer("peer_b").len(), 1);
    }

    #[test]
    fn byzantine_clear() {
        let mut det = ByzantineDetector::new();
        det.record_claim("p", 1, [0u8; 32]);
        det.record_auth_failure("p");
        assert_eq!(det.fault_count(), 1);
        det.clear();
        assert_eq!(det.fault_count(), 0);
    }

    #[test]
    fn byzantine_display() {
        let fmt = format!("{}", ByzantineFault::Equivocation {
            peer: "p1".into(),
            height: 10,
            root_a: [0u8; 32],
            root_b: [1u8; 32],
        });
        assert!(fmt.contains("equivocation"));
        assert!(fmt.contains("p1"));

        let fmt2 = format!("{}", ByzantineFault::AuthFailure { peer: "p2".into() });
        assert!(fmt2.contains("authentication failure"));
    }

    #[test]
    fn health_summary() {
        let mut reg = PeerRegistry::new();
        reg.add_peer("http://a:1".into());
        reg.add_peer("http://b:2".into());
        reg.mark_failure("http://b:2");
        reg.mark_failure("http://b:2");
        reg.mark_failure("http://b:2");

        let summary = reg.health_summary();
        assert_eq!(summary.total, 2);
        assert_eq!(summary.healthy, 1);
        assert_eq!(summary.unhealthy, 1);
    }

    // ── Quarantine tests ────────────────────────────────────────────

    #[test]
    fn quarantine_after_threshold_faults() {
        let mut det = ByzantineDetector::new();
        // Record 3 auth failures for the same peer.
        det.record_auth_failure("bad-peer");
        assert!(!det.is_quarantined("bad-peer"));
        det.record_auth_failure("bad-peer");
        assert!(!det.is_quarantined("bad-peer"));
        det.record_auth_failure("bad-peer");
        assert!(det.is_quarantined("bad-peer"));
    }

    #[test]
    fn quarantine_via_equivocation() {
        let mut det = ByzantineDetector::new();
        let root_a = [0xAAu8; 32];
        let root_b = [0xBBu8; 32];
        let root_c = [0xCCu8; 32];

        // 3 equivocations at different heights
        det.record_claim("evil", 1, root_a);
        det.record_claim("evil", 1, root_b); // fault 1
        det.record_claim("evil", 2, root_a);
        det.record_claim("evil", 2, root_c); // fault 2
        assert!(!det.is_quarantined("evil"));
        det.record_claim("evil", 3, root_a);
        det.record_claim("evil", 3, root_b); // fault 3
        assert!(det.is_quarantined("evil"));
    }

    #[test]
    fn quarantine_via_root_mismatch() {
        let mut det = ByzantineDetector::new();
        det.check_against_local("liar", 1, [0xAA; 32], [0xBB; 32]);
        det.check_against_local("liar", 2, [0xAA; 32], [0xCC; 32]);
        assert!(!det.is_quarantined("liar"));
        det.check_against_local("liar", 3, [0xAA; 32], [0xDD; 32]);
        assert!(det.is_quarantined("liar"));
    }

    #[test]
    fn lift_quarantine() {
        let mut det = ByzantineDetector::new();
        for _ in 0..3 { det.record_auth_failure("peer-x"); }
        assert!(det.is_quarantined("peer-x"));
        det.lift_quarantine("peer-x");
        assert!(!det.is_quarantined("peer-x"));
    }

    #[test]
    fn clear_resets_quarantine() {
        let mut det = ByzantineDetector::new();
        for _ in 0..3 { det.record_auth_failure("peer-y"); }
        assert!(det.is_quarantined("peer-y"));
        det.clear();
        assert!(!det.is_quarantined("peer-y"));
        assert_eq!(det.fault_count(), 0);
    }

    #[test]
    fn innocent_peer_not_quarantined() {
        let mut det = ByzantineDetector::new();
        // Record faults for different peers — none reaches threshold
        det.record_auth_failure("a");
        det.record_auth_failure("b");
        det.record_auth_failure("c");
        assert!(!det.is_quarantined("a"));
        assert!(!det.is_quarantined("b"));
        assert!(!det.is_quarantined("c"));
    }
}
