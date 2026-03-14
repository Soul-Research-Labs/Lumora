//! Bitcoin Script fragments for single-step verification.
//!
//! Each trace step type has a corresponding Script that takes the step's
//! input commitment + witness data and asserts the output commitment matches.
//! These scripts are embedded as Taproot leaf scripts in the disprove
//! transaction.
