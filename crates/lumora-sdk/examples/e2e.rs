//! End-to-end example: deposit → transfer → withdraw
//!
//! Demonstrates the full lifecycle of the Lumora privacy pool using the
//! high-level SDK.
//!
//! Run with:
//! ```sh
//! cargo run -p lumora-sdk --example e2e
//! ```

use lumora_note::keys::scalar_to_base;
use lumora_note::SpendingKey;
use lumora_sdk::Lumora;
use rand::rngs::OsRng;

fn main() {
    println!("=== Lumora end-to-end example ===\n");

    // ── 1. Initialize ──────────────────────────────────────────────
    println!("[1] Initialising (keygen for both circuits)...");
    let mut alice = Lumora::init();
    println!(
        "    Alice wallet created.  Pool balance: {}",
        alice.pool_balance()
    );

    // Create a second spending key for Bob (acts only as a recipient here).
    let bob_sk = SpendingKey::random(&mut OsRng);
    let bob_owner = scalar_to_base(bob_sk.inner());
    let bob_pk = bob_sk.public_key();

    // ── 2. Deposit ─────────────────────────────────────────────────
    println!("\n[2] Alice deposits 1000...");
    let dep1 = alice.deposit(500).expect("deposit 500");
    println!("    Deposit 500 at leaf {}", dep1.leaf_index);
    let dep2 = alice.deposit(500).expect("deposit 500");
    println!("    Deposit 500 at leaf {}", dep2.leaf_index);
    println!("    Pool balance: {}", alice.pool_balance());
    println!("    Alice wallet balance: {}", alice.balance());

    // ── 3. Private transfer (Alice → Bob) ──────────────────────────
    println!("\n[3] Alice sends 300 to Bob...");
    let send_res = alice
        .send(bob_owner, bob_pk, 300)
        .expect("send");
    println!(
        "    Transfer done. Output leaves: {:?}",
        send_res.receipt.leaf_indices
    );
    println!("    Alice wallet balance after send: {}", alice.balance());
    println!("    Pool balance (unchanged): {}", alice.pool_balance());

    // ── 4. Withdraw (Alice takes 200 out) ──────────────────────────
    println!("\n[4] Alice withdraws 200...");
    let recipient_addr = [0xABu8; 32]; // dummy rollup address
    let wd = alice.withdraw(200, recipient_addr).expect("withdraw");
    println!(
        "    Withdrawal done. Exit value: {}. Change leaves: {:?}",
        wd.receipt.amount, wd.receipt.change_leaf_indices
    );
    println!("    Alice wallet balance after withdraw: {}", alice.balance());
    println!("    Pool balance: {}", alice.pool_balance());

    // ── 5. Summary ─────────────────────────────────────────────────
    println!("\n=== Summary ===");
    println!("  Total commitments in tree: {}", alice.commitment_count());
    println!("  Nullifiers spent: 4 (2 per transfer, 2 per withdraw)");
    println!("  Pool balance: {} (1000 deposited - 200 withdrawn)", alice.pool_balance());
    println!("\nDone.");
}
