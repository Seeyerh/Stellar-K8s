//! Maintenance subsystems for Stellar nodes.
//!
//! The ledger archive pruning daemon lives here. [`fs`] abstracts the local
//! bucket directory so pruning is unit-testable without a real disk, and
//! [`pruner`] implements the retention-window logic on top of it.

pub mod fs;
pub mod pruner;

pub use fs::{parse_ledger_artifact, ArtifactKind, BucketFs, FileMeta, LedgerArtifact, StdBucketFs};
pub use pruner::{
    ArtifactGuard, ConfigError, CoreConfig, Decision, LedgerSource, NoLocks, PruneError,
    PrunePlan, PruneReport, Pruner, RetentionPolicy, ScannedArtifact, StaticLedger,
};
