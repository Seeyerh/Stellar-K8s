//! Filesystem abstraction for the ledger archive pruning daemon.
//!
//! The pruning daemon deletes files from a mounted history bucket directory, so
//! the whole subsystem is written against the [`BucketFs`] trait. Production
//! code uses [`StdBucketFs`]; tests use an in-memory fake and never touch a real
//! disk.
//!
//! # Artefact naming
//!
//! The scanner only ever considers files it can fully understand:
//!
//! * `ledger-<sequence>.xdr` / `ledger-<sequence>.xdr.gz` — a ledger file that
//!   embeds its own ledger sequence.
//! * `bucket-<sequence>-<hash256>.xdr` / `.xdr.gz` — a bucket file tagged with
//!   the ledger sequence that produced it and its 64-character content hash.
//! * `bucket-<hash256>.xdr` / `.xdr.gz` — a content-addressed bucket. It is
//!   recognised, but it carries **no** ledger sequence, so it is reported with
//!   `ledger_seq == None` and is never eligible for deletion. Content-addressed
//!   buckets can only be proven dead by resolving the bucket list at the
//!   retention boundary, which is out of scope for a name-based scan.
//!
//! Anything else ([`parse_ledger_artifact`] returns `None`) is left untouched,
//! so a typo or an unknown future artefact can never cause data loss.

use std::fs;
use std::io;
use std::path::Path;
use std::time::UNIX_EPOCH;

/// Length, in characters, of a hex-encoded 32-byte Stellar hash.
pub const HASH_HEX_LEN: usize = 64;

/// Metadata about one entry that lives in the bucket directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileMeta {
    /// File name only, without any directory component.
    pub name: String,
    /// Size of the file in bytes.
    pub size_bytes: u64,
    /// Last modification time as seconds since the Unix epoch, when available.
    pub modified_unix_secs: Option<u64>,
}

impl FileMeta {
    /// Build metadata for a bucket-directory entry.
    pub fn new(name: impl Into<String>, size_bytes: u64, modified_unix_secs: Option<u64>) -> Self {
        Self {
            name: name.into(),
            size_bytes,
            modified_unix_secs,
        }
    }
}

/// The category of ledger artefact a file name represents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArtifactKind {
    /// A bucket file (`bucket-...xdr`).
    Bucket,
    /// A ledger chain/header file (`ledger-...xdr`).
    Ledger,
}

/// A ledger artefact discovered in the bucket directory.
///
/// Only artefacts with `ledger_seq == Some(_)` can ever be pruned. A
/// content-addressed bucket is reported with `ledger_seq == None` because its
/// age cannot be proven from the name alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerArtifact {
    /// File name the artefact was parsed from.
    pub name: String,
    /// Whether this is a bucket or a ledger file.
    pub kind: ArtifactKind,
    /// Ledger sequence embedded in the name, when present.
    pub ledger_seq: Option<u64>,
    /// Content hash for content-addressed bucket names, when present.
    pub hash: Option<String>,
}

/// Parse a bucket-directory file name into a [`LedgerArtifact`].
///
/// Returns `None` for every name the scanner does not explicitly understand.
/// Callers must treat `None` as "preserve": never delete on ambiguity.
pub fn parse_ledger_artifact(name: &str) -> Option<LedgerArtifact> {
    let stem = strip_xdr_suffix(name)?;

    if let Some(rest) = stem.strip_prefix("ledger-") {
        if !is_decimal(rest) {
            return None;
        }
        return Some(LedgerArtifact {
            name: name.to_string(),
            kind: ArtifactKind::Ledger,
            ledger_seq: Some(rest.parse::<u64>().ok()?),
            hash: None,
        });
    }

    if let Some(rest) = stem.strip_prefix("bucket-") {
        return match rest.split_once('-') {
            // `bucket-<ledger>-<hash>`: sequence-tagged bucket file.
            Some((seq, hash)) => {
                if !is_decimal(seq) || !is_hex(hash, HASH_HEX_LEN) {
                    return None;
                }
                Some(LedgerArtifact {
                    name: name.to_string(),
                    kind: ArtifactKind::Bucket,
                    ledger_seq: Some(seq.parse::<u64>().ok()?),
                    hash: Some(hash.to_string()),
                })
            }
            // `bucket-<hash>`: content-addressed, ledger sequence unknown.
            None => {
                if !is_hex(rest, HASH_HEX_LEN) {
                    return None;
                }
                Some(LedgerArtifact {
                    name: name.to_string(),
                    kind: ArtifactKind::Bucket,
                    ledger_seq: None,
                    hash: Some(rest.to_string()),
                })
            }
        };
    }

    None
}

/// Strip an optional `.gz` suffix followed by the mandatory `.xdr` suffix.
fn strip_xdr_suffix(name: &str) -> Option<&str> {
    let stem = name.strip_suffix(".gz").unwrap_or(name);
    stem.strip_suffix(".xdr")
}

/// True when `value` is exactly `len` ASCII hex characters.
fn is_hex(value: &str, len: usize) -> bool {
    value.len() == len && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// True when `value` is a non-empty decimal integer.
fn is_decimal(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit())
}

/// Minimal filesystem surface the pruning daemon depends on.
///
/// Implementations must be **idempotent**: deleting a file that no longer
/// exists is `Ok(())`, so a pruning run that is cancelled and retried can never
/// fail because of its own earlier progress.
pub trait BucketFs {
    /// List the regular files in `dir`.
    ///
    /// A directory that does not exist yields an empty list rather than an
    /// error, because "nothing to prune" is not a failure.
    fn list(&self, dir: &Path) -> io::Result<Vec<FileMeta>>;

    /// Delete a single file. Idempotent; see the trait contract.
    fn delete(&self, path: &Path) -> io::Result<()>;
}

/// [`BucketFs`] implementation backed by [`std::fs`].
#[derive(Clone, Copy, Debug, Default)]
pub struct StdBucketFs;

impl BucketFs for StdBucketFs {
    fn list(&self, dir: &Path) -> io::Result<Vec<FileMeta>> {
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => return Err(err),
        };

        let mut files = Vec::new();
        for entry in entries {
            let entry = entry?;
            let metadata = entry.metadata()?;
            if !metadata.is_file() {
                continue;
            }
            let modified_unix_secs = metadata
                .modified()
                .ok()
                .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                .map(|duration| duration.as_secs());
            files.push(FileMeta::new(
                entry.file_name().to_string_lossy().into_owned(),
                metadata.len(),
                modified_unix_secs,
            ));
        }
        files.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(files)
    }

    fn delete(&self, path: &Path) -> io::Result<()> {
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            // Already gone: the deletion is idempotent.
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    #[test]
    fn parses_ledger_sequence_variants() {
        let plain = parse_ledger_artifact("ledger-123456.xdr").expect("ledger file");
        assert_eq!(plain.kind, ArtifactKind::Ledger);
        assert_eq!(plain.ledger_seq, Some(123456));
        assert_eq!(plain.hash, None);

        let gzipped = parse_ledger_artifact("ledger-0.xdr.gz").expect("gzipped ledger file");
        assert_eq!(gzipped.ledger_seq, Some(0));
        assert_eq!(gzipped.kind, ArtifactKind::Ledger);
    }

    #[test]
    fn parses_sequence_tagged_bucket() {
        let name = format!("bucket-42-{HASH}.xdr.gz");
        let artifact = parse_ledger_artifact(&name).expect("sequence-tagged bucket");
        assert_eq!(artifact.kind, ArtifactKind::Bucket);
        assert_eq!(artifact.ledger_seq, Some(42));
        assert_eq!(artifact.hash.as_deref(), Some(HASH));
    }

    #[test]
    fn parses_content_addressed_bucket_without_sequence() {
        let name = format!("bucket-{HASH}.xdr");
        let artifact = parse_ledger_artifact(&name).expect("content-addressed bucket");
        assert_eq!(artifact.kind, ArtifactKind::Bucket);
        assert_eq!(artifact.ledger_seq, None);
        assert_eq!(artifact.hash.as_deref(), Some(HASH));
    }

    #[test]
    fn rejects_unrecognised_names() {
        for name in [
            "README.md",
            "bucket-list",
            "ledger-abc.xdr",
            "ledger-.xdr",
            "bucket-42-short.xdr",
            "bucket-42-00112233445566778899aabbccddeeff.xdr", // 32 hex, not 64
            "bucket-not-a-hash.xdr",
            "history-abc.xdr.gz",
            "bucket-42-.xdr",
            "ledger-42.txt",
        ] {
            assert!(
                parse_ledger_artifact(name).is_none(),
                "{name} must not be recognised"
            );
        }
    }

    #[test]
    fn rejects_hex_hash_that_is_not_a_sequence_tag() {
        // Two dashes means the first segment must be a decimal sequence.
        let name = format!("bucket-{HASH}-{HASH}.xdr");
        assert!(parse_ledger_artifact(&name).is_none());
    }
}
