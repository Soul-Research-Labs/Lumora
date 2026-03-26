//! Incremental Merkle tree with Poseidon hash.
//!
//! Stores note commitments in a fixed-depth binary tree.
//! Supports:
//! - `insert(leaf)` — append a new commitment
//! - `root()` — current Merkle root
//! - `witness(index)` — authentication path for a leaf
//! - `verify(root, leaf, index, path)` — static membership verification
//!
//! Depth = 32 → capacity = 2^32 ≈ 4 billion notes.
//!
//! Empty leaves use a canonical "zero" value chain:
//!   zero[0] = 0
//!   zero[i] = PoseidonHash(zero[i-1], zero[i-1])

use pasta_curves::pallas;
use serde::{Serialize, Deserialize};

use lumora_primitives::poseidon;

/// Error type returned by fallible tree operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TreeError {
    /// The tree has reached its maximum capacity (2^DEPTH leaves).
    TreeFull,
}

/// Tree depth. 2^32 ≈ 4 billion leaf capacity.
pub const DEPTH: usize = 32;

/// Precomputed "empty subtree" hashes for each level.
/// `ZEROS[i]` = the root of an empty subtree of depth `i`.
fn zeros() -> [pallas::Base; DEPTH + 1] {
    let mut z = [pallas::Base::zero(); DEPTH + 1];
    // z[0] = 0 (empty leaf)
    for i in 1..=DEPTH {
        z[i] = poseidon::hash_two(z[i - 1], z[i - 1]);
    }
    z
}

/// An authentication path: sibling hashes from leaf to root.
#[derive(Clone, Debug)]
pub struct MerklePath {
    /// Sibling hash at each level (index 0 = leaf level).
    pub siblings: [pallas::Base; DEPTH],
    /// The index of the leaf (determines left/right at each level).
    pub index: u64,
}

impl MerklePath {
    /// Verify that `leaf` at `self.index` produces the given `root`.
    pub fn verify(&self, root: pallas::Base, leaf: pallas::Base) -> bool {
        let computed = self.compute_root(leaf);
        computed == root
    }

    /// Compute the root from the leaf and authentication path.
    pub fn compute_root(&self, leaf: pallas::Base) -> pallas::Base {
        let mut current = leaf;
        let mut idx = self.index;
        for i in 0..DEPTH {
            let sibling = self.siblings[i];
            current = if idx & 1 == 0 {
                poseidon::hash_two(current, sibling)
            } else {
                poseidon::hash_two(sibling, current)
            };
            idx >>= 1;
        }
        current
    }
}

/// An incremental (append-only) Merkle tree.
///
/// We don't store the entire 2^32 tree in memory. Instead we keep:
/// - All inserted leaves (for witness generation)
/// - The "filled subtree" hashes at each level (for efficient root computation)
///
/// This is the same technique used in Tornado Cash / Semaphore.
#[derive(Clone, Serialize, Deserialize)]
pub struct IncrementalMerkleTree {
    /// Number of leaves inserted so far.
    next_index: u64,
    /// `filled[i]` = the hash of the last completed subtree at level `i`.
    #[serde(with = "lumora_primitives::serde_field::base_array")]
    filled: [pallas::Base; DEPTH],
    /// Precomputed zero hashes.
    #[serde(skip, default = "zeros")]
    zeros: [pallas::Base; DEPTH + 1],
    /// All inserted leaves (needed for witness generation).
    #[serde(with = "lumora_primitives::serde_field::base_vec")]
    leaves: Vec<pallas::Base>,
    /// Cache of internal node hashes: `(node_index, level) → hash`.
    /// Populated lazily by `node_hash` and invalidated on insert.
    #[serde(skip, default)]
    node_cache: std::collections::HashMap<(u64, usize), pallas::Base>,
    /// Indices of leaves known to be spent (nullified).
    /// Used by `prune_cache` to evict internal-node cache entries for
    /// fully-spent subtrees, reducing memory usage.
    #[serde(default)]
    spent_leaves: std::collections::HashSet<u64>,
}

impl IncrementalMerkleTree {
    /// Create a new empty tree.
    pub fn new() -> Self {
        Self {
            next_index: 0,
            filled: [pallas::Base::zero(); DEPTH],
            zeros: zeros(),
            leaves: Vec::new(),
            node_cache: std::collections::HashMap::new(),
            spent_leaves: std::collections::HashSet::new(),
        }
    }

    /// Number of leaves inserted.
    pub fn len(&self) -> u64 {
        self.next_index
    }

    /// Whether the tree is empty.
    pub fn is_empty(&self) -> bool {
        self.next_index == 0
    }

    /// Insert a leaf, returning `Ok(index)` or `Err(TreeError::TreeFull)` if the tree is full.
    pub fn try_insert(&mut self, leaf: pallas::Base) -> Result<u64, TreeError> {
        if self.next_index >= (1u64 << DEPTH) {
            return Err(TreeError::TreeFull);
        }

        let index = self.next_index;
        self.leaves.push(leaf);

        // Invalidate cached nodes along the path from this leaf to root.
        {
            let mut node_idx = index;
            for level in 0..DEPTH {
                // Invalidate the parent that contains this node.
                let parent = node_idx >> 1;
                self.node_cache.remove(&(parent, level + 1));
                // Also invalidate sibling's parent chain.
                node_idx >>= 1;
            }
        }

        // Update filled subtrees.
        let mut current = leaf;
        let mut idx = index;
        for i in 0..DEPTH {
            if idx & 1 == 0 {
                self.filled[i] = current;
                current = poseidon::hash_two(current, self.zeros[i]);
            } else {
                current = poseidon::hash_two(self.filled[i], current);
            }
            idx >>= 1;
        }

        self.next_index += 1;
        Ok(index)
    }

    /// Insert a leaf, returns the leaf's index.
    ///
    /// # Panics
    /// Panics if the tree is full (2^DEPTH leaves have been inserted).
    pub fn insert(&mut self, leaf: pallas::Base) -> u64 {
        self.try_insert(leaf).expect("Merkle tree is full")
    }

    /// Compute the current root.
    pub fn root(&mut self) -> pallas::Base {
        if self.next_index == 0 {
            return self.zeros[DEPTH];
        }
        // Recompute by walking up from the last insertion.
        // This is O(DEPTH) which is fine.
        // Safety: next_index > 0 guarantees leaves is non-empty.
        let last_leaf = self.leaves[self.leaves.len() - 1];
        self.compute_root_at(self.next_index - 1, last_leaf)
    }

    /// Compute what the root would be with `leaf` at `index`.
    fn compute_root_at(&mut self, index: u64, leaf: pallas::Base) -> pallas::Base {
        let path = self.witness(index).expect("index should be valid");
        path.compute_root(leaf)
    }

    /// Generate an authentication path for the leaf at `index`.
    pub fn witness(&mut self, index: u64) -> Option<MerklePath> {
        if index >= self.next_index {
            return None;
        }

        let mut siblings = [pallas::Base::zero(); DEPTH];

        for (level, sibling) in siblings.iter_mut().enumerate().take(DEPTH) {
            let sibling_idx = index_sibling_at_level(index, level);
            *sibling = self.node_hash(sibling_idx, level);
        }

        Some(MerklePath {
            siblings,
            index,
        })
    }

    /// Get the hash of the node at (node_index, level).
    /// Level 0 = leaf level. Level DEPTH = root.
    fn node_hash(&mut self, node_index: u64, level: usize) -> pallas::Base {
        // If this entire subtree is beyond the filled region, return precomputed zero.
        let leftmost_leaf = node_index << level;
        if leftmost_leaf >= self.next_index {
            return self.zeros[level];
        }

        if level == 0 {
            return self.leaves[node_index as usize];
        }

        // Check cache first.
        if let Some(&cached) = self.node_cache.get(&(node_index, level)) {
            return cached;
        }

        // Internal node: hash of its two children.
        let left_child = node_index * 2;
        let right_child = left_child + 1;
        let left = self.node_hash(left_child, level - 1);
        let right = self.node_hash(right_child, level - 1);
        let hash = poseidon::hash_two(left, right);
        self.node_cache.insert((node_index, level), hash);
        hash
    }

    /// Mark a leaf index as spent (nullified).
    ///
    /// This doesn't change the tree structure or root — the leaf value is
    /// preserved. However, it enables `prune_cache` to reclaim memory for
    /// internal nodes in fully-spent subtrees.
    pub fn mark_spent(&mut self, leaf_index: u64) {
        if leaf_index < self.next_index {
            self.spent_leaves.insert(leaf_index);
        }
    }

    /// Check whether a leaf has been marked as spent.
    pub fn is_spent(&self, leaf_index: u64) -> bool {
        self.spent_leaves.contains(&leaf_index)
    }

    /// Number of leaves marked as spent.
    pub fn spent_count(&self) -> usize {
        self.spent_leaves.len()
    }

    /// Prune internal-node cache entries for fully-spent subtrees.
    ///
    /// Walks up from spent leaves and evicts cached hashes for subtrees
    /// where all leaves are spent. Returns the number of cache entries evicted.
    ///
    /// This reclaims memory without changing the tree structure or root.
    pub fn prune_cache(&mut self) -> usize {
        let mut evicted = 0;

        // For each cache level, check if the subtree rooted at that node is fully spent.
        let keys: Vec<(u64, usize)> = self.node_cache.keys().copied().collect();
        for (node_index, level) in keys {
            let leftmost = node_index << level;
            let subtree_size = 1u64 << level;
            let rightmost = leftmost + subtree_size;

            // Check if every leaf in [leftmost, rightmost) is spent.
            let all_spent = (leftmost..rightmost.min(self.next_index))
                .all(|i| self.spent_leaves.contains(&i));

            if all_spent && leftmost < self.next_index {
                self.node_cache.remove(&(node_index, level));
                evicted += 1;
            }
        }

        evicted
    }
}

impl Default for IncrementalMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

/// Given a leaf index and a level, return the index of the sibling node at that level.
fn index_sibling_at_level(leaf_index: u64, level: usize) -> u64 {
    let node_index = leaf_index >> level;
    node_index ^ 1 // flip the lowest bit to get the sibling
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn empty_tree_root_is_deterministic() {
        let mut t1 = IncrementalMerkleTree::new();
        let mut t2 = IncrementalMerkleTree::new();
        assert_eq!(t1.root(), t2.root());
    }

    #[test]
    fn insert_changes_root() {
        let mut tree = IncrementalMerkleTree::new();
        let r0 = tree.root();
        tree.insert(pallas::Base::from(42u64));
        let r1 = tree.root();
        assert_ne!(r0, r1);
    }

    #[test]
    fn witness_verifies() {
        let mut tree = IncrementalMerkleTree::new();
        let leaf = pallas::Base::from(12345u64);
        let idx = tree.insert(leaf);
        let root = tree.root();
        let path = tree.witness(idx).unwrap();
        assert!(path.verify(root, leaf));
    }

    #[test]
    fn witness_fails_for_wrong_leaf() {
        let mut tree = IncrementalMerkleTree::new();
        let leaf = pallas::Base::from(12345u64);
        let idx = tree.insert(leaf);
        let root = tree.root();
        let path = tree.witness(idx).unwrap();
        let wrong_leaf = pallas::Base::from(99999u64);
        assert!(!path.verify(root, wrong_leaf));
    }

    #[test]
    fn multiple_inserts_all_verify() {
        let mut tree = IncrementalMerkleTree::new();
        let leaves: Vec<pallas::Base> = (0..16)
            .map(|i| pallas::Base::from(i as u64 + 1))
            .collect();
        let indices: Vec<u64> = leaves.iter().map(|l| tree.insert(*l)).collect();
        let root = tree.root();
        for (i, &leaf) in leaves.iter().enumerate() {
            let path = tree.witness(indices[i]).unwrap();
            assert!(
                path.verify(root, leaf),
                "Leaf {} should verify against current root",
                i
            );
        }
    }

    #[test]
    fn witness_out_of_bounds_returns_none() {
        let mut tree = IncrementalMerkleTree::new();
        assert!(tree.witness(0).is_none());
    }

    // -- Property-based tests --

    proptest! {
        /// Every inserted leaf gets a valid witness against the final root.
        #[test]
        fn prop_insert_witness_valid(values in prop::collection::vec(1u64..u64::MAX, 1..16)) {
            let mut tree = IncrementalMerkleTree::new();
            let indices: Vec<u64> = values.iter()
                .map(|&v| tree.insert(pallas::Base::from(v)))
                .collect();
            let root = tree.root();
            for (i, &v) in values.iter().enumerate() {
                let path = tree.witness(indices[i]).unwrap();
                prop_assert!(path.verify(root, pallas::Base::from(v)),
                    "leaf {} must verify", i);
            }
        }

        /// Leaf indices are assigned sequentially starting from 0.
        #[test]
        fn prop_sequential_indices(n in 1usize..64) {
            let mut tree = IncrementalMerkleTree::new();
            for expected in 0..n {
                let idx = tree.insert(pallas::Base::from(expected as u64));
                prop_assert_eq!(idx, expected as u64);
            }
            prop_assert_eq!(tree.len(), n as u64);
        }

        /// Root changes with each unique leaf insertion.
        #[test]
        fn prop_insert_changes_root(a in 1u64..u64::MAX, b in 1u64..u64::MAX) {
            prop_assume!(a != b);
            let mut tree = IncrementalMerkleTree::new();
            let r0 = tree.root();
            tree.insert(pallas::Base::from(a));
            let r1 = tree.root();
            tree.insert(pallas::Base::from(b));
            let r2 = tree.root();
            prop_assert_ne!(r0, r1);
            prop_assert_ne!(r1, r2);
        }

        /// Witness for wrong leaf value must fail verification.
        #[test]
        fn prop_wrong_leaf_rejects(val in 1u64..u64::MAX, wrong in 1u64..u64::MAX) {
            prop_assume!(val != wrong);
            let mut tree = IncrementalMerkleTree::new();
            let idx = tree.insert(pallas::Base::from(val));
            let root = tree.root();
            let path = tree.witness(idx).unwrap();
            prop_assert!(!path.verify(root, pallas::Base::from(wrong)));
        }
    }
}
