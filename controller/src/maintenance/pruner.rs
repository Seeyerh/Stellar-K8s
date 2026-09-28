//! Automated Ledger Archive Pruning Daemon
//!
//! Reads the Stellar Core configuration to derive the minimum ledger retention
//! window, scans the node's bucket directory, and deletes ledger artefacts that
//! are provably below the retention boundary.
//!
//! # Safety guarantees
//!
//! 1. **No retention window, no pruning.** If `CATCHUP_RECENT` is absent from
//!    the Stellar Core config the daemon refuses to run rather than guessing a
//!    window and deleting data.
//! 2. **Exclusive boundary.** An artefact is deletable only when its ledger
//!    sequence is *strictly* below `latest_ledger - retention_window`. The
//!    artefact sitting exactly on the boundary is always kept.
//! 3. **Never delete on ambiguity.** Unrecognisable names, names whose ledger
//!    sequence cannot be derived, and artefacts reported as locked/in-use by the
//!    injected [`ArtifactGuard`] are preserved.
//! 4. **Idempotent and cancellation-safe.** Deletions go through
//!    [`BucketFs::delete`], which treats an already-removed file as success, and
//!    the guard is re-checked at delete time to close the scan/apply race.
//! 5. **Errors never abort a run.** A failed deletion is recorded in
//!    [`PruneReport::errors`] and the remaining artefacts are still processed.

use std::collections::HashSet;
use std::fmt;
use std::path::{Path, PathBuf};

use super::fs::{parse_ledger_artifact, ArtifactKind, BucketFs};

/// Default Stellar Core bucket directory (`BUCKET_DIR_PATH`).
pub const DEFAULT_BUCKET_DIR: &str = "/var/lib/stellar/buckets";

// ---------------------------------------------------------------------------
// Stellar Core configuration
// ---------------------------------------------------------------------------

/// Errors raised while parsing `stellar-core.cfg`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigError {
    /// `CATCHUP_RECENT` was not present, so the retention window is unknown.
    MissingRetention,
    /// A recognised key carried a value that could not be parsed.
    InvalidValue {
        /// Configuration key, upper-cased.
        key: String,
        /// Raw value that failed to parse.
        value: String,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::MissingRetention => write!(
                f,
                "stellar-core config does not set CATCHUP_RECENT; refusing to prune"
            ),
            ConfigError::InvalidValue { key, value } => {
                write!(f, "invalid value {value:?} for {key}")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

/// The subset of the Stellar Core configuration the pruning daemon needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreConfig {
    /// `CATCHUP_RECENT`: minimum number of recent ledgers to retain.
    pub catchup_recent: u64,
    /// Optional explicit override, `HISTORY_RETENTION_LEDGERS`.
    pub history_retention_ledgers: Option<u64>,
    /// `BUCKET_DIR_PATH`: directory holding local bucket/ledger artifacts.
    pub bucket_dir: PathBuf,
}

impl CoreConfig {
    /// Parse a Stellar Core config from its text form.
    ///
    /// The parser is intentionally tiny and tolerant: it understands
    /// `KEY = VALUE` lines and `[section]` headers, ignores comments, and only
    /// validates the keys the pruner acts on. Unknown keys are ignored.
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let mut catchup_recent = None;
        let mut history_retention_ledgers = None;
        let mut bucket_dir = None;

        for raw in text.lines() {
            let line = strip_comment(raw).trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let key = key.trim().to_ascii_uppercase();
            let value = unquote(value.trim());
            match key.as_str() {
                "CATCHUP_RECENT" => catchup_recent = Some(parse_u64(&key, value)?),
                "HISTORY_RETENTION_LEDGERS" => {
                    history_retention_ledgers = Some(parse_u64(&key, value)?)
                }
                "BUCKET_DIR_PATH" => bucket_dir = Some(PathBuf::from(value)),
                _ => {}
            }
        }

        Ok(Self {
            catchup_recent: catchup_recent.ok_or(ConfigError::MissingRetention)?,
            history_retention_ledgers,
            bucket_dir: bucket_dir.unwrap_or_else(|| PathBuf::from(DEFAULT_BUCKET_DIR)),
        })
    }

    /// The effective retention window in ledgers.
    pub fn retention_window(&self) -> u64 {
        self.history_retention_ledgers.unwrap_or(self.catchup_recent)
    }

    /// Build the retention policy for the node's current ledger.
    pub fn retention_policy(&self, latest_ledger: u64) -> RetentionPolicy {
        RetentionPolicy::new(latest_ledger, self.retention_window())
    }
}

/// Strip a `#` comment while respecting quoted values.
fn strip_comment(line: &str) -> &str {
    let mut quote = None;
    for (index, ch) in line.char_indices() {
        match ch {
            '"' | '\'' if quote == Some(ch) => quote = None,
            '"' | '\'' if quote.is_none() => quote = Some(ch),
            '#' if quote.is_none() => return &line[..index],
            _ => {}
        }
    }
    line
}

/// Remove one layer of matching single or double quotes.
fn unquote(value: &str) -> &str {
    let bytes = value.as_bytes();
    if bytes.len() >= 2 {
        let (first, last) = (bytes[0], bytes[bytes.len() - 1]);
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return &value[1..value.len() - 1];
        }
    }
    value
}

/// Parse a `u64` config value, mapping failures to [`ConfigError`].
fn parse_u64(key: &str, value: &str) -> Result<u64, ConfigError> {
    value.parse::<u64>().map_err(|_| ConfigError::InvalidValue {
        key: key.to_string(),
        value: value.to_string(),
    })
}

// ---------------------------------------------------------------------------
// Retention policy
// ---------------------------------------------------------------------------

/// The ledger boundary below which artefacts may be deleted.
///
/// The boundary is **exclusive**: an artefact whose sequence equals
/// `boundary_ledger` is part of the retained window and is kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetentionPolicy {
    /// Ledgers strictly below this sequence are eligible for deletion.
    pub boundary_ledger: u64,
    /// Retention window in ledgers that produced the boundary.
    pub window: u64,
}

impl RetentionPolicy {
    /// Derive the boundary from the node's latest ledger and retention window.
    pub fn new(latest_ledger: u64, window: u64) -> Self {
        Self {
            boundary_ledger: latest_ledger.saturating_sub(window),
            window,
        }
    }

    /// An artefact is deletable only when it is strictly below the boundary.
    pub fn is_deletable(&self, ledger_seq: u64) -> bool {
        ledger_seq < self.boundary_ledger
    }
}

// ---------------------------------------------------------------------------
// Injected dependencies
// ---------------------------------------------------------------------------

/// Source of the node's latest ledger sequence.
pub trait LedgerSource {
    /// Latest ledger known to the node (`/info` or the database).
    fn latest_ledger(&self) -> Result<u64, PruneError>;
}

/// [`LedgerSource`] returning a fixed sequence; useful for plans and tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StaticLedger {
    /// The sequence this source always reports.
    pub sequence: u64,
}

impl LedgerSource for StaticLedger {
    fn latest_ledger(&self) -> Result<u64, PruneError> {
        Ok(self.sequence)
    }
}

/// Tells the pruner which artefacts are in use and must be preserved.
///
/// Implementations answer "is this file currently needed by a running catchup,
/// a Horizon node, or the active quorum/bucket list?".
pub trait ArtifactGuard {
    /// Returns `true` when `name` must not be deleted.
    fn is_locked(&self, name: &str) -> bool;
}

/// [`ArtifactGuard`] that protects nothing.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoLocks;

impl ArtifactGuard for NoLocks {
    fn is_locked(&self, _name: &str) -> bool {
        false
    }
}

impl ArtifactGuard for HashSet<String> {
    fn is_locked(&self, name: &str) -> bool {
        self.contains(name)
    }
}

// ---------------------------------------------------------------------------
// Errors and results
// ---------------------------------------------------------------------------

/// A single error encountered while listing or deleting artefacts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PruneError {
    /// Artefact the error relates to, when it is not a run-level failure.
    pub artifact: Option<String>,
    /// Human-readable description.
    pub message: String,
}

impl PruneError {
    /// A run-level error not tied to one artefact.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            artifact: None,
            message: message.into(),
        }
    }

    /// An error tied to one artefact.
    pub fn for_artifact(name: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            artifact: Some(name.into()),
            message: message.into(),
        }
    }
}

impl fmt::Display for PruneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.artifact {
            Some(name) => write!(f, "artifact {name}: {}", self.message),
            None => write!(f, "{}", self.message),
        }
    }
}

impl std::error::Error for PruneError {}

/// What the pruner decided to do with one artefact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Below the retention boundary and not locked: delete it.
    Delete,
    /// At or above the boundary: part of the retained window.
    PreserveInRetention,
    /// Reported as in-use by the [`ArtifactGuard`].
    PreserveLocked,
    /// Recognised artefact with no ledger sequence in its name.
    PreserveUnknownLedger,
    /// Name the scanner does not understand.
    PreserveUnrecognised,
}

/// One classified artefact in a [`PrunePlan`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScannedArtifact {
    /// File name.
    pub name: String,
    /// Size in bytes.
    pub size_bytes: u64,
    /// Ledger sequence parsed from the name, when present.
    pub ledger_seq: Option<u64>,
    /// Artefact kind parsed from the name, when recognised.
    pub kind: Option<ArtifactKind>,
    /// What the pruner intends to do with it.
    pub decision: Decision,
}

/// The result of a dry scan: what would be deleted and why.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PrunePlan {
    /// Every artefact seen, with its decision.
    pub artifacts: Vec<ScannedArtifact>,
    /// Total bytes that [`Pruner::apply`] would reclaim.
    pub deletable_bytes: u64,
}

impl PrunePlan {
    /// Number of artefacts with the given decision.
    pub fn count(&self, decision: Decision) -> usize {
        self.artifacts
            .iter()
            .filter(|artifact| artifact.decision == decision)
            .count()
    }

    /// Number of artefacts that would be deleted.
    pub fn deletable_count(&self) -> usize {
        self.count(Decision::Delete)
    }

    /// Iterate the artefacts that would be deleted.
    pub fn deletable(&self) -> impl Iterator<Item = &ScannedArtifact> {
        self.artifacts
            .iter()
            .filter(|artifact| artifact.decision == Decision::Delete)
    }
}

/// Structured outcome of applying a [`PrunePlan`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PruneReport {
    /// Artefacts considered.
    pub scanned: usize,
    /// Artefacts successfully deleted.
    pub deleted: usize,
    /// Bytes reclaimed by successful deletions.
    pub bytes_reclaimed: u64,
    /// Artefacts preserved because they are inside the retention window.
    pub retained: usize,
    /// Artefacts preserved because the guard reported them in-use.
    pub locked: usize,
    /// Artefacts preserved because their ledger sequence is unknown.
    pub unknown_ledger: usize,
    /// Artefacts preserved because their name was not understood.
    pub unrecognised: usize,
    /// Deletion errors; a non-empty list does not abort the run.
    pub errors: Vec<PruneError>,
}

impl PruneReport {
    /// Total artefacts intentionally preserved.
    pub fn preserved(&self) -> usize {
        self.retained + self.locked + self.unknown_ledger + self.unrecognised
    }

    /// True when no deletion failed.
    pub fn is_success(&self) -> bool {
        self.errors.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Pruner
// ---------------------------------------------------------------------------

/// Scans a bucket directory and deletes artefacts below the retention boundary.
pub struct Pruner<F, L, G> {
    fs: F,
    ledger: L,
    guard: G,
    config: CoreConfig,
}

impl<F, L, G> Pruner<F, L, G>
where
    F: BucketFs,
    L: LedgerSource,
    G: ArtifactGuard,
{
    /// Build a pruner from its filesystem, ledger source, guard and config.
    pub fn new(fs: F, ledger: L, guard: G, config: CoreConfig) -> Self {
        Self {
            fs,
            ledger,
            guard,
            config,
        }
    }

    /// The directory this pruner operates on.
    pub fn bucket_dir(&self) -> &Path {
        &self.config.bucket_dir
    }

    /// Classify every artefact without mutating the filesystem.
    pub fn scan(&self) -> Result<PrunePlan, PruneError> {
        let latest_ledger = self.ledger.latest_ledger()?;
        let policy = self.config.retention_policy(latest_ledger);
        let entries = self.fs.list(&self.config.bucket_dir).map_err(|err| {
            PruneError::new(format!(
                "failed to list {}: {err}",
                self.config.bucket_dir.display()
            ))
        })?;

        let mut plan = PrunePlan::default();
        for entry in entries {
            let (decision, ledger_seq, kind) = self.classify(&entry.name, policy);
            if decision == Decision::Delete {
                plan.deletable_bytes += entry.size_bytes;
            }
            plan.artifacts.push(ScannedArtifact {
                name: entry.name,
                size_bytes: entry.size_bytes,
                ledger_seq,
                kind,
                decision,
            });
        }
        Ok(plan)
    }

    /// Apply a plan, deleting every artefact classified as deletable.
    pub fn apply(&self, plan: &PrunePlan) -> PruneReport {
        self.apply_batched(plan, usize::MAX)
    }

    /// Apply a plan in bounded batches.
    ///
    /// Each deletion is independent and idempotent, so a caller driving this
    /// from an async supervisor can yield between batches without risking
    /// partial or duplicated work.
    pub fn apply_batched(&self, plan: &PrunePlan, batch_size: usize) -> PruneReport {
        let batch = batch_size.max(1);
        let mut report = PruneReport {
            scanned: plan.artifacts.len(),
            ..PruneReport::default()
        };

        for artifact in &plan.artifacts {
            match artifact.decision {
                Decision::PreserveInRetention => {
                    report.retained += 1;
                    continue;
                }
                Decision::PreserveLocked => {
                    report.locked += 1;
                    continue;
                }
                Decision::PreserveUnknownLedger => {
                    report.unknown_ledger += 1;
                    continue;
                }
                Decision::PreserveUnrecognised => {
                    report.unrecognised += 1;
                    continue;
                }
                Decision::Delete => {}
            }

            // Close the scan/apply race: a file may have been locked by a
            // catchup that started after the plan was built.
            if self.guard.is_locked(&artifact.name) {
                report.locked += 1;
                continue;
            }

            let path = self.config.bucket_dir.join(&artifact.name);
            match self.fs.delete(&path) {
                Ok(()) => {
                    report.deleted += 1;
                    report.bytes_reclaimed += artifact.size_bytes;
                }
                Err(err) => report
                    .errors
                    .push(PruneError::for_artifact(artifact.name.clone(), err.to_string())),
            }

            if report.deleted % batch == 0 {
                std::thread::yield_now();
            }
        }

        report
    }

    /// Scan and apply in one call.
    pub fn run(&self) -> Result<PruneReport, PruneError> {
        let plan = self.scan()?;
        Ok(self.apply(&plan))
    }

    /// Classify a single artefact.
    fn classify(&self, name: &str, policy: RetentionPolicy) -> (Decision, Option<u64>, Option<ArtifactKind>) {
        let Some(artifact) = parse_ledger_artifact(name) else {
            return (Decision::PreserveUnrecognised, None, None);
        };
        let Some(seq) = artifact.ledger_seq else {
            return (Decision::PreserveUnknownLedger, None, Some(artifact.kind));
        };
        if self.guard.is_locked(name) {
            (Decision::PreserveLocked, Some(seq), Some(artifact.kind))
        } else if policy.is_deletable(seq) {
            (Decision::Delete, Some(seq), Some(artifact.kind))
        } else {
            (Decision::PreserveInRetention, Some(seq), Some(artifact.kind))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::maintenance::fs::{BucketFs, FileMeta};
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::io;
    use std::rc::Rc;

    const BUCKET_DIR: &str = "/var/lib/stellar/buckets";
    const HASH: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    #[derive(Default)]
    struct FakeState {
        files: HashMap<String, FileMeta>,
        fail_delete: HashSet<String>,
        delete_calls: Vec<String>,
    }

    /// In-memory [`BucketFs`] so every pruning test runs without a real disk.
    #[derive(Clone, Default)]
    struct FakeFs {
        state: Rc<RefCell<FakeState>>,
    }

    impl FakeFs {
        fn with_files(files: &[(&str, u64)]) -> Self {
            let fake = Self::default();
            {
                let mut state = fake.state.borrow_mut();
                for (name, size) in files {
                    state.files.insert(
                        (*name).to_string(),
                        FileMeta::new(*name, *size, Some(1_700_000_000)),
                    );
                }
            }
            fake
        }

        fn fail_on(&self, name: &str) {
            self.state.borrow_mut().fail_delete.insert(name.to_string());
        }

        fn remaining(&self) -> Vec<String> {
            let mut names: Vec<String> = self.state.borrow().files.keys().cloned().collect();
            names.sort();
            names
        }

        fn delete_calls(&self) -> Vec<String> {
            self.state.borrow().delete_calls.clone()
        }
    }

    impl BucketFs for FakeFs {
        fn list(&self, _dir: &Path) -> io::Result<Vec<FileMeta>> {
            let mut files: Vec<FileMeta> = self.state.borrow().files.values().cloned().collect();
            files.sort_by(|a, b| a.name.cmp(&b.name));
            Ok(files)
        }

        fn delete(&self, path: &Path) -> io::Result<()> {
            let name = path
                .file_name()
                .expect("file name")
                .to_string_lossy()
                .into_owned();
            let mut state = self.state.borrow_mut();
            state.delete_calls.push(name.clone());
            if state.fail_delete.contains(&name) {
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, "denied"));
            }
            // Idempotent: removing a missing file still succeeds.
            state.files.remove(&name);
            Ok(())
        }
    }

    fn config(catchup_recent: u64) -> CoreConfig {
        CoreConfig {
            catchup_recent,
            history_retention_ledgers: None,
            bucket_dir: PathBuf::from(BUCKET_DIR),
        }
    }

    fn pruner<G: ArtifactGuard>(fs: FakeFs, latest: u64, guard: G) -> Pruner<FakeFs, StaticLedger, G> {
        Pruner::new(fs, StaticLedger { sequence: latest }, guard, config(100))
    }

    /// Locks on the second observation of its target, simulating a catchup that
    /// starts between `scan` and `apply`.
    struct SecondCallGuard {
        name: String,
        hits: RefCell<usize>,
    }

    impl SecondCallGuard {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                hits: RefCell::new(0),
            }
        }
    }

    impl ArtifactGuard for SecondCallGuard {
        fn is_locked(&self, name: &str) -> bool {
            if name != self.name {
                return false;
            }
            let mut hits = self.hits.borrow_mut();
            *hits += 1;
            *hits >= 2
        }
    }

    #[test]
    fn deletes_obsolete_and_preserves_recent() {
        let fs = FakeFs::with_files(&[("ledger-100.xdr", 11), ("ledger-950.xdr", 22)]);
        // latest 1000, window 100 => boundary 900.
        let pruner = pruner(fs.clone(), 1000, NoLocks);

        let report = pruner.run().expect("run");

        assert_eq!(report.deleted, 1);
        assert_eq!(report.bytes_reclaimed, 11);
        assert_eq!(report.retained, 1);
        assert!(report.is_success());
        assert_eq!(fs.remaining(), vec!["ledger-950.xdr".to_string()]);
    }

    #[test]
    fn retention_boundary_is_exclusive() {
        // boundary is exactly 900: 899 is deletable, 900 is not.
        let fs = FakeFs::with_files(&[("ledger-899.xdr", 1), ("ledger-900.xdr", 1)]);
        let pruner = pruner(fs.clone(), 1000, NoLocks);

        let report = pruner.run().expect("run");

        assert_eq!(report.deleted, 1);
        assert_eq!(report.retained, 1);
        assert_eq!(fs.remaining(), vec!["ledger-900.xdr".to_string()]);
    }

    #[test]
    fn unparseable_names_are_preserved() {
        let tagged = format!("bucket-950-{HASH}.xdr");
        let fs = FakeFs::with_files(&[
            ("README.md", 1),
            ("bucket-nothex.xdr", 1),
            ("ledger-abc.xdr", 1),
            ("ledger-42.txt", 1),
            (tagged.as_str(), 1),
        ]);
        let pruner = pruner(fs.clone(), 1000, NoLocks);

        let report = pruner.run().expect("run");

        assert_eq!(report.deleted, 0);
        assert_eq!(report.unrecognised, 4);
        // The one valid sequence-tagged bucket is inside the window.
        assert_eq!(report.retained, 1);
        assert!(report.is_success());
    }

    #[test]
    fn content_addressed_bucket_is_never_deleted() {
        let name = format!("bucket-{HASH}.xdr");
        let fs = FakeFs::with_files(&[(name.as_str(), 4096)]);
        let pruner = pruner(fs.clone(), 1000, NoLocks);

        let report = pruner.run().expect("run");

        assert_eq!(report.deleted, 0);
        assert_eq!(report.unknown_ledger, 1);
        assert_eq!(fs.remaining().len(), 1);
    }

    #[test]
    fn locked_files_are_preserved() {
        let locked: HashSet<String> = ["ledger-100.xdr".to_string()].into_iter().collect();
        let fs = FakeFs::with_files(&[("ledger-100.xdr", 7), ("ledger-200.xdr", 9)]);
        let pruner = pruner(fs.clone(), 1000, locked);

        let report = pruner.run().expect("run");

        assert_eq!(report.locked, 1);
        assert_eq!(report.deleted, 1);
        assert_eq!(report.bytes_reclaimed, 9);
        assert_eq!(fs.remaining(), vec!["ledger-100.xdr".to_string()]);
    }

    #[test]
    fn file_locked_after_scan_is_preserved_at_delete_time() {
        let guard = SecondCallGuard::new("ledger-100.xdr");
        let fs = FakeFs::with_files(&[("ledger-100.xdr", 7)]);
        let pruner = Pruner::new(
            fs.clone(),
            StaticLedger { sequence: 1000 },
            guard,
            config(100),
        );

        let report = pruner.run().expect("run");

        assert_eq!(report.deleted, 0);
        assert_eq!(report.locked, 1);
        assert_eq!(fs.remaining(), vec!["ledger-100.xdr".to_string()]);
    }

    #[test]
    fn rerun_is_idempotent() {
        let fs = FakeFs::with_files(&[("ledger-100.xdr", 5)]);
        let pruner = pruner(fs.clone(), 1000, NoLocks);

        let first = pruner.run().expect("first run");
        let second = pruner.run().expect("second run");

        assert_eq!(first.deleted, 1);
        assert_eq!(first.bytes_reclaimed, 5);
        assert_eq!(second.deleted, 0);
        assert_eq!(second.bytes_reclaimed, 0);
        assert_eq!(second.scanned, 0);
        assert!(second.is_success());
    }

    #[test]
    fn delete_errors_are_aggregated_without_aborting() {
        let fs = FakeFs::with_files(&[("ledger-1.xdr", 10), ("ledger-2.xdr", 20), ("ledger-3.xdr", 30)]);
        fs.fail_on("ledger-2.xdr");
        let pruner = pruner(fs.clone(), 1000, NoLocks);

        let report = pruner.run().expect("run");

        assert_eq!(report.deleted, 2);
        assert_eq!(report.bytes_reclaimed, 40);
        assert_eq!(report.errors.len(), 1);
        assert!(!report.is_success());
        assert_eq!(
            report.errors[0].artifact.as_deref(),
            Some("ledger-2.xdr")
        );
        assert_eq!(fs.remaining(), vec!["ledger-2.xdr".to_string()]);
    }

    #[test]
    fn batched_apply_processes_every_deletable_artifact() {
        let fs = FakeFs::with_files(&[
            ("ledger-1.xdr", 1),
            ("ledger-2.xdr", 1),
            ("ledger-3.xdr", 1),
            ("ledger-4.xdr", 1),
        ]);
        let pruner = pruner(fs.clone(), 1000, NoLocks);

        let plan = pruner.scan().expect("scan");
        let report = pruner.apply_batched(&plan, 2);

        assert_eq!(report.deleted, 4);
        assert_eq!(report.bytes_reclaimed, 4);
        assert!(fs.remaining().is_empty());
        assert_eq!(fs.delete_calls().len(), 4);
    }

    #[test]
    fn plan_classifies_every_artifact_exactly_once() {
        let tagged = format!("bucket-50-{HASH}.xdr");
        let fs = FakeFs::with_files(&[
            ("ledger-10.xdr", 1),
            ("ledger-995.xdr", 1),
            ("bucket-abc.xdr", 1),
            (tagged.as_str(), 1),
        ]);
        let pruner = pruner(fs, 1000, NoLocks);

        let plan = pruner.scan().expect("scan");

        assert_eq!(plan.artifacts.len(), 4);
        assert_eq!(plan.deletable_count(), 2);
        assert_eq!(plan.deletable_bytes, 2);
        assert_eq!(plan.count(Decision::PreserveInRetention), 1);
        assert_eq!(plan.count(Decision::PreserveUnrecognised), 1);
    }

    #[test]
    fn parses_config_and_defaults_bucket_dir() {
        let text = r#"
# stellar-core.cfg
CATCHUP_RECENT = 100   # keep roughly 100 ledgers

[HISTORY.local]
get = "curl http://example.invalid/{0}"
"#;
        let config = CoreConfig::parse(text).expect("parse");
        assert_eq!(config.catchup_recent, 100);
        assert_eq!(config.bucket_dir, PathBuf::from(DEFAULT_BUCKET_DIR));
        assert_eq!(config.retention_window(), 100);
    }

    #[test]
    fn history_retention_override_wins() {
        let config = CoreConfig::parse(
            "CATCHUP_RECENT = 100\nHISTORY_RETENTION_LEDGERS = 5000\nBUCKET_DIR_PATH = \"/mnt/buckets\"\n",
        )
        .expect("parse");

        assert_eq!(config.retention_window(), 5000);
        assert_eq!(config.bucket_dir, PathBuf::from("/mnt/buckets"));
        assert_eq!(config.retention_policy(10_000).boundary_ledger, 5_000);
    }

    #[test]
    fn missing_retention_refuses_to_prune() {
        let error = CoreConfig::parse("BUCKET_DIR_PATH = \"/mnt/buckets\"\n").expect_err("must fail");
        assert_eq!(error, ConfigError::MissingRetention);
    }

    #[test]
    fn invalid_retention_value_is_rejected() {
        let error = CoreConfig::parse("CATCHUP_RECENT = soon\n").expect_err("must fail");
        assert_eq!(
            error,
            ConfigError::InvalidValue {
                key: "CATCHUP_RECENT".to_string(),
                value: "soon".to_string(),
            }
        );
    }

    #[test]
    fn retention_boundary_saturates_below_zero() {
        let policy = RetentionPolicy::new(50, 100);
        assert_eq!(policy.boundary_ledger, 0);
        assert!(!policy.is_deletable(0));
    }
}
