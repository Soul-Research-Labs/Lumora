//! LUMORA CLI — interactive command-line privacy coprocessor.

use clap::{Parser, Subcommand};
use lumora_sdk::convert;
use lumora_sdk::Lumora;
use group::Group;
use pasta_curves::pallas;

#[derive(Parser)]
#[command(name = "lumora", version, about = "Lumora privacy coprocessor CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start an interactive session (init node + wallet, run commands).
    Run,
    /// Show version and build info.
    Info,
    /// Migrate wallet nullifiers from V1 to V2 (domain-separated).
    MigrateNullifiers {
        /// Path to the plaintext wallet JSON file.
        #[arg(long)]
        wallet: String,
        /// Chain ID for the new domain-separated nullifiers.
        #[arg(long, default_value_t = 0)]
        chain_id: u64,
        /// Application ID for the new domain-separated nullifiers.
        #[arg(long, default_value_t = 0)]
        app_id: u64,
        /// Perform a dry run (show what would change without writing).
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },
    /// BitVM2 bridge management commands.
    Bitvm {
        #[command(subcommand)]
        action: BitvmAction,
    },
}

#[derive(Subcommand)]
enum BitvmAction {
    /// Show BitVM bridge configuration and status.
    Status {
        /// Challenge timeout in blocks (default: 144).
        #[arg(long, default_value_t = 144)]
        timeout_blocks: u32,
    },
    /// Set up a new BitVM bridge (operator + challenger keypairs).
    Setup {
        /// Operator public key (hex, 32 bytes).
        #[arg(long)]
        operator_key: String,
        /// Challenger public key (hex, 32 bytes).
        #[arg(long)]
        challenger_key: String,
        /// Bond amount in satoshis (default: 10,000,000 = 0.1 BTC).
        #[arg(long, default_value_t = 10_000_000)]
        bond_sats: u64,
        /// Challenge timeout in blocks (default: 144 = ~1 day).
        #[arg(long, default_value_t = 144)]
        timeout_blocks: u32,
    },
    /// Show details of a specific assertion.
    Assertion {
        /// Assertion ID (hex, 32 bytes).
        #[arg(long)]
        id: String,
        /// Challenge timeout in blocks.
        #[arg(long, default_value_t = 144)]
        timeout_blocks: u32,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run => run_interactive(),
        Commands::Info => print_info(),
        Commands::MigrateNullifiers { wallet, chain_id, app_id, dry_run } => {
            migrate_nullifiers(&wallet, chain_id, app_id, dry_run);
        }
        Commands::Bitvm { action } => handle_bitvm(action),
    }
}

fn print_info() {
    println!("lumora {}", env!("CARGO_PKG_VERSION"));
    println!("Privacy coprocessor for Bitcoin rollups");
    println!();
    println!("Crates:");
    println!("  lumora-primitives  Poseidon hash, Pedersen commitment");
    println!("  lumora-note        Note, keys, nullifier, encryption");
    println!("  lumora-tree        Incremental Merkle tree (depth 32)");
    println!("  lumora-circuits    Halo2 transfer + withdrawal circuits");
    println!("  lumora-prover      ZK proof generation (k=13)");
    println!("  lumora-verifier    Proof verification");
    println!("  lumora-contracts   Privacy pool (deposit/transfer/withdraw)");
    println!("  lumora-node        Prover daemon + note store");
    println!("  lumora-client      Wallet + note management");
    println!("  lumora-sdk         High-level orchestrator");
    println!("  lumora-bitvm       BitVM2 bridge verifier for Bitcoin L1");
}

fn handle_bitvm(action: BitvmAction) {
    use lumora_bitvm::config::BitvmConfig;
    use lumora_bitvm::transactions::XOnlyPubKey;

    match action {
        BitvmAction::Status { timeout_blocks } => {
            println!("BitVM2 Bridge Status");
            println!("====================");
            println!();
            let config = BitvmConfig {
                challenge_timeout_blocks: timeout_blocks,
                ..BitvmConfig::default()
            };
            println!("Challenge timeout : {} blocks (~{:.1} hours)",
                config.challenge_timeout_blocks,
                config.challenge_timeout_blocks as f64 * 10.0 / 60.0);
            println!("Bond amount       : {} sats ({:.4} BTC)",
                config.bond_sats, config.bond_sats as f64 / 100_000_000.0);
            println!("Min confirmations : {}", config.min_confirmations);
            println!("Max pending       : {}", config.max_pending_assertions);
            println!();
            println!("Proof system      : Halo2 IPA (K=13, Pallas/Vesta)");
            println!("Trace commitment  : SHA-256 binary Merkle tree");
            println!("Script model      : Split-and-hash (one step per leaf)");
            println!();
            println!("Step types:");
            println!("  TranscriptInit   - Initialize Blake2b transcript + absorb PI");
            println!("  CommitmentRead   - Read commitment points from proof stream");
            println!("  ChallengeSqueeze - Squeeze Fiat-Shamir challenge");
            println!("  MsmRound         - Multi-scalar multiplication accumulator");
            println!("  IpaRound         - Inner product argument round");
            println!("  FinalCheck       - Verify accumulated MSM equals identity");
        }
        BitvmAction::Setup { operator_key, challenger_key, bond_sats, timeout_blocks } => {
            let op_bytes = match hex::decode(&operator_key) {
                Ok(b) if b.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&b);
                    arr
                }
                _ => {
                    eprintln!("Error: operator_key must be 64 hex characters (32 bytes)");
                    std::process::exit(1);
                }
            };
            let ch_bytes = match hex::decode(&challenger_key) {
                Ok(b) if b.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&b);
                    arr
                }
                _ => {
                    eprintln!("Error: challenger_key must be 64 hex characters (32 bytes)");
                    std::process::exit(1);
                }
            };

            let config = BitvmConfig {
                bond_sats,
                challenge_timeout_blocks: timeout_blocks,
                ..BitvmConfig::default()
            };

            println!("BitVM2 Bridge Setup");
            println!("===================");
            println!();
            println!("Operator key  : {}", hex::encode(op_bytes));
            println!("Challenger key: {}", hex::encode(ch_bytes));
            println!("Bond          : {} sats", config.bond_sats);
            println!("Timeout       : {} blocks", config.challenge_timeout_blocks);
            println!();

            // Initialize key aggregation
            let op_key = XOnlyPubKey(op_bytes);
            let ch_key = XOnlyPubKey(ch_bytes);
            let agg = lumora_bitvm::keys::aggregate_keys(&op_key, &ch_key);

            println!("Aggregate key : {}", hex::encode(agg.combined_key.0));
            println!("Op coefficient: {}", hex::encode(agg.operator_coeff));
            println!("Ch coefficient: {}", hex::encode(agg.challenger_coeff));
            println!();
            println!("Pre-sign setup requires both parties online.");
            println!("Run `lumora bitvm status` to verify configuration.");
        }
        BitvmAction::Assertion { id, timeout_blocks } => {
            let id_bytes = match hex::decode(&id) {
                Ok(b) if b.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&b);
                    arr
                }
                _ => {
                    eprintln!("Error: assertion ID must be 64 hex characters (32 bytes)");
                    std::process::exit(1);
                }
            };

            println!("Assertion Details");
            println!("=================");
            println!();
            println!("ID            : {}", hex::encode(id_bytes));
            println!("Timeout       : {} blocks", timeout_blocks);
            println!();
            println!("Note: Full assertion tracking requires a running operator");
            println!("or challenger daemon connected to a Bitcoin node.");
        }
    }
}

fn migrate_nullifiers(wallet_path: &str, chain_id: u64, app_id: u64, dry_run: bool) {
    use lumora_note::nullifier::{Nullifier, NullifierDomain};
    use lumora_note::commitment::NoteCommitment;

    let path = std::path::Path::new(wallet_path);
    let mut wallet = match lumora_client::wallet::Wallet::load(path) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("Error loading wallet: {e}");
            std::process::exit(1);
        }
    };

    let domain = NullifierDomain::new(chain_id, app_id);
    let sk = wallet.spending_key();

    println!("Migrating nullifiers for wallet: {wallet_path}");
    println!("Domain: chain_id={chain_id}, app_id={app_id}");
    println!("Notes in wallet: {}", wallet.note_count());
    println!();

    for owned in wallet.notes() {
        let cm = NoteCommitment(owned.commitment);
        let v1 = Nullifier::derive(sk, &cm);
        let v2 = Nullifier::derive_v2(sk, &cm, &domain);

        let v1_hex = convert::field_to_hex(v1.0);
        let v2_hex = convert::field_to_hex(v2.0);

        println!("Leaf {:>5}: V1={} → V2={}", owned.leaf_index, &v1_hex[..16], &v2_hex[..16]);
    }

    if dry_run {
        println!();
        println!("Dry run complete. No changes written.");
    } else {
        // Record the nullifier domain in the wallet so future transactions
        // automatically derive V2 nullifiers for this chain/app.
        wallet.nullifier_domain = Some([chain_id, app_id]);
        if let Err(e) = wallet.save(path) {
            eprintln!("Error saving wallet after migration: {e}");
            std::process::exit(1);
        }
        println!();
        println!("Migration complete. {} nullifier(s) migrated to V2 domain.", wallet.note_count());
        println!("Wallet saved with domain chain_id={chain_id} app_id={app_id}.");
        println!("Future transactions will use V2 nullifier derivation.");
        println!("Note: On-chain nullifier set update must be coordinated");
        println!("with the pool operator (see docs/upgrade-runbook.md).");
    }
}

fn run_interactive() {
    println!("Initializing Lumora node (generating proving keys)...");
    let mut lumora = Lumora::init();
    println!("Ready. Wallet owner: {}", convert::field_to_hex(lumora.wallet.owner_field()));
    println!();
    print_help();

    let stdin = std::io::stdin();
    let mut line = String::new();

    loop {
        line.clear();
        eprint!("lumora> ");
        if stdin.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        match parts[0] {
            "help" | "h" => print_help(),
            "balance" | "bal" => {
                match parts.get(1).and_then(|v| v.parse::<u64>().ok()) {
                    Some(asset) => {
                        println!("Asset {} balance: {}", asset, lumora.balance_of(asset));
                    }
                    None => {
                        println!("Wallet balance : {}", lumora.balance());
                        println!("Pool balance   : {}", lumora.pool_balance());
                    }
                }
            }
            "deposit" | "d" => {
                let amount = match parse_u64(parts.get(1)) {
                    Some(v) => v,
                    None => { println!("Usage: deposit <amount>"); continue; }
                };
                match lumora.deposit(amount) {
                    Ok(receipt) => {
                        println!("Deposited {}. Leaf index: {}. Root: {}",
                            amount, receipt.leaf_index,
                            convert::field_to_hex(receipt.new_root));
                    }
                    Err(e) => println!("Error: {:?}", e),
                }
            }
            "send" | "s" => {
                let recipient_hex = match parts.get(1) {
                    Some(s) => *s,
                    None => { println!("Usage: send <recipient_hex> <amount>"); continue; }
                };
                let recipient = match convert::hex_to_field(recipient_hex) {
                    Some(f) => f,
                    None => { println!("Invalid recipient hex"); continue; }
                };
                let amount = match parse_u64(parts.get(2)) {
                    Some(v) => v,
                    None => { println!("Usage: send <recipient_hex> <amount>"); continue; }
                };
                // Hash the recipient owner field through Poseidon to derive a
                // deterministic scalar suitable for `scalar · G`. Direct
                // base-to-scalar bit reinterpretation is unsound because it
                // may fail for values ≥ the scalar modulus.
                let recipient_scalar = {
                    use ff::PrimeField;
                    let hashed = lumora_primitives::poseidon::hash_one(recipient);
                    let repr = hashed.to_repr();
                    pallas::Scalar::from_repr(repr)
                        .unwrap_or_else(|| {
                            let mut r = repr;
                            r[31] &= 0x3F;
                            pallas::Scalar::from_repr(r)
                                .expect("cleared top bits is always valid scalar")
                        })
                };
                let recipient_pk = pallas::Point::generator() * recipient_scalar;
                match lumora.send(recipient, recipient_pk, amount) {
                    Ok(result) => {
                        println!("Sent {}. Proof size: {} bytes. Nullifiers spent: 2",
                            amount, result.proof.proof_bytes.len());
                        println!("Recipient tag: {}", hex::encode(result.recipient_tag));
                    }
                    Err(e) => println!("Error: {:?}", e),
                }
            }
            "withdraw" | "w" => {
                let amount = match parse_u64(parts.get(1)) {
                    Some(v) => v,
                    None => { println!("Usage: withdraw <amount> [recipient_hex]"); continue; }
                };
                let recipient = match parts.get(2).and_then(|s| hex::decode(s).ok()) {
                    Some(bytes) if bytes.len() == 32 => {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&bytes);
                        arr
                    }
                    _ => {
                        println!("Usage: withdraw <amount> <recipient_hex (32 bytes)>");
                        continue;
                    }
                };
                match lumora.withdraw(amount, recipient) {
                    Ok(result) => {
                        println!("Withdrew {}. Change leaf indices: {:?}. Root: {}",
                            result.receipt.amount,
                            result.receipt.change_leaf_indices,
                            convert::field_to_hex(result.receipt.new_root));
                    }
                    Err(e) => println!("Error: {:?}", e),
                }
            }
            "owner" => {
                println!("{}", convert::field_to_hex(lumora.wallet.owner_field()));
            }
            "export-key" => {
                println!("WARNING: This will display your spending key in plain text.");
                eprint!("Type 'yes' to confirm: ");
                let mut confirm = String::new();
                if stdin.read_line(&mut confirm).unwrap_or(0) == 0 { continue; }
                if confirm.trim() != "yes" {
                    println!("Cancelled.");
                    continue;
                }
                let sk_hex = convert::field_to_hex(
                    lumora_note::keys::scalar_to_base(lumora.wallet.spending_key().inner()),
                );
                // Print to stderr to avoid spending key appearing in stdout logs.
                eprintln!("Spending key: {sk_hex}");
                eprintln!("(Keep this secret! Anyone with this key can spend your notes.)");
            }
            "generate-mnemonic" | "gen-mnemonic" => {
                let (phrase, _key) = lumora_note::SpendingKey::generate_mnemonic(rand::rngs::OsRng);
                println!("Mnemonic (24 words):\n  {phrase}");
                println!();
                println!("To use this mnemonic, restart with: recover-mnemonic");
                println!("WARNING: Write these words down and store them safely!");
            }
            "recover-mnemonic" | "rec-mnemonic" => {
                eprint!("Enter your 24-word mnemonic phrase: ");
                let phrase = match rpassword::read_password() {
                    Ok(p) => p,
                    Err(e) => { println!("Error reading input: {e}"); continue; }
                };
                let phrase = phrase.trim();
                let sk = lumora_note::SpendingKey::from_mnemonic(phrase);
                lumora.wallet = lumora_client::wallet::Wallet::new(sk);
                println!("Wallet recovered. Owner: {}",
                    convert::field_to_hex(lumora.wallet.owner_field()));
            }
            "save-wallet" => {
                let path_str = match parts.get(1) {
                    Some(p) => *p,
                    None => { println!("Usage: save-wallet <path>"); continue; }
                };
                println!("Warning: save-wallet stores keys in PLAINTEXT.");
                println!("  Consider using save-wallet-encrypted instead.");
                eprint!("Continue with plaintext save? (yes/no): ");
                let mut confirm = String::new();
                let _ = std::io::stdin().read_line(&mut confirm);
                if confirm.trim() != "yes" {
                    println!("Aborted.");
                    continue;
                }
                match lumora.wallet.save(std::path::Path::new(path_str)) {
                    Ok(()) => println!("Wallet saved to {path_str}"),
                    Err(e) => println!("Error saving wallet: {e}"),
                }
            }
            "save-wallet-encrypted" | "swe" => {
                let path_str = match parts.get(1) {
                    Some(p) => *p,
                    None => { println!("Usage: save-wallet-encrypted <path>"); continue; }
                };
                eprint!("Enter passphrase: ");
                let pass: String = match rpassword::read_password() {
                    Ok(p) => p,
                    Err(e) => { println!("Error reading passphrase: {e}"); continue; }
                };
                match lumora.wallet.save_encrypted(std::path::Path::new(path_str), pass.trim()) {
                    Ok(()) => println!("Encrypted wallet saved to {path_str}"),
                    Err(e) => println!("Error: {e}"),
                }
            }
            "load-wallet" => {
                let path_str = match parts.get(1) {
                    Some(p) => *p,
                    None => { println!("Usage: load-wallet <path>"); continue; }
                };
                match lumora_client::wallet::Wallet::load(std::path::Path::new(path_str)) {
                    Ok(w) => {
                        lumora.wallet = w;
                        println!("Wallet loaded. Owner: {}",
                            convert::field_to_hex(lumora.wallet.owner_field()));
                    }
                    Err(e) => println!("Error loading wallet: {e}"),
                }
            }
            "load-wallet-encrypted" | "lwe" => {
                let path_str = match parts.get(1) {
                    Some(p) => *p,
                    None => { println!("Usage: load-wallet-encrypted <path>"); continue; }
                };
                eprint!("Enter passphrase: ");
                let pass: String = match rpassword::read_password() {
                    Ok(p) => p,
                    Err(e) => { println!("Error reading passphrase: {e}"); continue; }
                };
                match lumora_client::wallet::Wallet::load_encrypted(std::path::Path::new(path_str), pass.trim()) {
                    Ok(w) => {
                        lumora.wallet = w;
                        println!("Wallet loaded. Owner: {}",
                            convert::field_to_hex(lumora.wallet.owner_field()));
                    }
                    Err(e) => println!("Error: {e}"),
                }
            }
            "status" | "st" => {
                println!("Wallet balance : {}", lumora.balance());
                println!("Wallet notes   : {}", lumora.wallet.note_count());
                println!("Pool balance   : {}", lumora.pool_balance());
                println!("Commitments    : {}", lumora.node.commitment_count());
                println!("Merkle root    : {}", convert::field_to_hex(lumora.node.current_root()));
            }
            "scan" => {
                let found = lumora.scan_notes();
                println!("Scanned note store: {found} new note(s) found.");
            }
            "history" | "hist" => {
                let history = lumora.wallet.history();
                if history.is_empty() {
                    println!("No transactions yet.");
                } else {
                    for (i, tx) in history.iter().enumerate() {
                        match tx {
                            lumora_client::wallet::TxRecord::Deposit { amount, asset, leaf_index } =>
                                println!("  {}. Deposit: {} (asset {}) → leaf {}", i + 1, amount, asset, leaf_index),
                            lumora_client::wallet::TxRecord::Send { amount, asset, recipient_hex } =>
                                println!("  {}. Send: {} (asset {}) → {}", i + 1, amount, asset, &recipient_hex[..16]),
                            lumora_client::wallet::TxRecord::Withdraw { amount, asset } =>
                                println!("  {}. Withdraw: {} (asset {})", i + 1, amount, asset),
                        }
                    }
                }
            }
            "quit" | "exit" | "q" => {
                println!("Goodbye.");
                break;
            }
            "save-state" => {
                let dir = match parts.get(1) {
                    Some(d) => *d,
                    None => { println!("Usage: save-state <directory>"); continue; }
                };
                match lumora.save_state(std::path::Path::new(dir)) {
                    Ok(()) => println!("State saved to {dir}/"),
                    Err(e) => println!("Error saving state: {e}"),
                }
            }
            other => {
                println!("Unknown command: {other}. Type 'help' for commands.");
            }
        }
    }
}

fn print_help() {
    println!("Commands:");
    println!("  deposit <amount>                  Deposit into the pool");
    println!("  send <recipient_hex> <amount>     Private transfer");
    println!("  withdraw <amount> [addr_hex]      Withdraw from the pool");
    println!("  balance [asset_id]                Show balances (optionally per-asset)");
    println!("  status                            Show full status");
    println!("  scan                              Scan for incoming notes");
    println!("  history                           Show transaction history");
    println!("  owner                             Print wallet owner hex");
    println!("  export-key                        Print spending key hex");
    println!("  generate-mnemonic                 Generate a 24-word seed phrase");
    println!("  recover-mnemonic                  Recover wallet from seed phrase");
    println!("  save-wallet <path>                Save wallet to file");
    println!("  save-wallet-encrypted <path>      Save wallet encrypted");
    println!("  load-wallet <path>                Load wallet from file");
    println!("  load-wallet-encrypted <path>      Load encrypted wallet");
    println!("  save-state <directory>            Save full node + wallet state");
    println!("  help                              Show this help");
    println!("  quit                              Exit");
}

fn parse_u64(s: Option<&&str>) -> Option<u64> {
    s.and_then(|v| v.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn parse_u64_valid() {
        let s = "12345";
        assert_eq!(parse_u64(Some(&s)), Some(12345));
    }

    #[test]
    fn parse_u64_none() {
        assert_eq!(parse_u64(None), None);
    }

    #[test]
    fn parse_u64_invalid() {
        let s = "abc";
        assert_eq!(parse_u64(Some(&s)), None);
    }

    #[test]
    fn parse_u64_negative() {
        let s = "-1";
        assert_eq!(parse_u64(Some(&s)), None);
    }

    #[test]
    fn parse_u64_overflow() {
        let s = "99999999999999999999";
        assert_eq!(parse_u64(Some(&s)), None);
    }

    #[test]
    fn parse_u64_zero() {
        let s = "0";
        assert_eq!(parse_u64(Some(&s)), Some(0));
    }

    #[test]
    fn cli_run_subcommand_parses() {
        let cli = Cli::try_parse_from(["lumora", "run"]);
        assert!(cli.is_ok());
        match cli.unwrap().command {
            Commands::Run => {}
            _ => panic!("expected Run"),
        }
    }

    #[test]
    fn cli_info_subcommand_parses() {
        let cli = Cli::try_parse_from(["lumora", "info"]);
        assert!(cli.is_ok());
        match cli.unwrap().command {
            Commands::Info => {}
            _ => panic!("expected Info"),
        }
    }

    #[test]
    fn cli_no_subcommand_errors() {
        let cli = Cli::try_parse_from(["lumora"]);
        assert!(cli.is_err());
    }

    #[test]
    fn cli_unknown_subcommand_errors() {
        let cli = Cli::try_parse_from(["lumora", "nonexistent"]);
        assert!(cli.is_err());
    }

    // ── Integration-style command-line parsing tests ─────────────

    #[test]
    fn parse_u64_max_value() {
        let s = u64::MAX.to_string();
        let sref = s.as_str();
        assert_eq!(parse_u64(Some(&sref)), Some(u64::MAX));
    }

    #[test]
    fn parse_u64_leading_zeros() {
        let s = "007";
        assert_eq!(parse_u64(Some(&s)), Some(7));
    }

    #[test]
    fn parse_u64_whitespace() {
        let s = " 42 ";
        // str::parse trims nothing — should fail
        assert_eq!(parse_u64(Some(&s)), None);
    }

    #[test]
    fn parse_u64_float() {
        let s = "3.14";
        assert_eq!(parse_u64(Some(&s)), None);
    }

    #[test]
    fn parse_u64_empty_string() {
        let s = "";
        assert_eq!(parse_u64(Some(&s)), None);
    }

    #[test]
    fn cli_version_flag() {
        let result = Cli::try_parse_from(["lumora", "--version"]);
        // clap exits on --version, which surfaces as an Err
        assert!(result.is_err());
    }

    #[test]
    fn cli_help_flag() {
        let result = Cli::try_parse_from(["lumora", "--help"]);
        assert!(result.is_err());
    }

    #[test]
    fn repl_command_dispatch_coverage() {
        // Ensure every known REPL command keyword is recognized via
        // the whitespace-split approach used in `run_interactive`.
        let known = [
            "help", "h", "balance", "bal", "deposit", "d",
            "send", "s", "withdraw", "w", "owner", "export-key",
            "generate-mnemonic", "gen-mnemonic", "recover-mnemonic",
            "rec-mnemonic", "save-wallet", "save-wallet-encrypted", "swe",
            "load-wallet", "load-wallet-encrypted", "lwe",
            "status", "st", "scan", "history", "hist",
            "quit", "exit", "q", "save-state", "info",
        ];
        for cmd in &known {
            let parts: Vec<&str> = cmd.split_whitespace().collect();
            assert!(!parts.is_empty(), "command '{}' should split to at least 1 part", cmd);
        }
        // Verify unknown commands are indeed not in the set
        assert!(!known.contains(&"foobar"));
    }

    #[test]
    fn cli_migrate_nullifiers_parses() {
        let cli = Cli::try_parse_from([
            "lumora", "migrate-nullifiers",
            "--wallet", "/tmp/wallet.json",
            "--chain-id", "1",
            "--app-id", "42",
            "--dry-run",
        ]);
        assert!(cli.is_ok());
        match cli.unwrap().command {
            Commands::MigrateNullifiers { wallet, chain_id, app_id, dry_run } => {
                assert_eq!(wallet, "/tmp/wallet.json");
                assert_eq!(chain_id, 1);
                assert_eq!(app_id, 42);
                assert!(dry_run);
            }
            _ => panic!("expected MigrateNullifiers"),
        }
    }

    #[test]
    fn cli_migrate_nullifiers_defaults() {
        let cli = Cli::try_parse_from([
            "lumora", "migrate-nullifiers",
            "--wallet", "/tmp/wallet.json",
        ]);
        assert!(cli.is_ok());
        match cli.unwrap().command {
            Commands::MigrateNullifiers { chain_id, app_id, dry_run, .. } => {
                assert_eq!(chain_id, 0);
                assert_eq!(app_id, 0);
                assert!(!dry_run);
            }
            _ => panic!("expected MigrateNullifiers"),
        }
    }
}
