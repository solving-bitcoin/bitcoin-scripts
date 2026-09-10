//! Resolved Git dependency identities from the Cargo.lock embedded at build time.
//!
//! Rebuilding after a lockfile change updates these values. An already compiled
//! binary continues to report its embedded lockfile, even if the file on disk
//! changes. This identifies the resolved source, not local edits in a Cargo Git
//! checkout. Path overrides and ambiguous package names fail explicitly.
//!
//! The small parser accepts Cargo's generated, single-line quoted identity
//! fields. It deliberately rejects unsupported string escapes rather than
//! guessing their meaning, and does not treat unused patches as dependencies.

use std::{error::Error, fmt};

const LOCKFILE: &str = include_str!("../../Cargo.lock");

/// One uniquely resolved Git package in the embedded lockfile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DependencyProvenance<'a> {
    pub name: &'a str,
    pub version: &'a str,
    /// Complete Cargo source, including its reference query and resolved commit.
    pub source: &'a str,
    /// Resolved 40-digit commit after `#`, not a branch, tag, or `rev` query.
    pub commit: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvenanceError {
    MissingPackage(String),
    DuplicatePackage(String),
    MissingField {
        package: String,
        field: &'static str,
    },
    MalformedField {
        package: String,
        field: &'static str,
    },
    NonGitSource(String),
    InvalidGitSource(String),
}

impl fmt::Display for ProvenanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingPackage(name) => write!(f, "no resolved package named {name} in embedded Cargo.lock"),
            Self::DuplicatePackage(name) => write!(f, "multiple resolved packages named {name} in embedded Cargo.lock"),
            Self::MissingField { package, field } => write!(f, "missing {field} for {package} in embedded Cargo.lock"),
            Self::MalformedField { package, field } => write!(f, "malformed or duplicate {field} for {package} in embedded Cargo.lock"),
            Self::NonGitSource(name) => write!(f, "resolved package {name} does not have a Git source"),
            Self::InvalidGitSource(name) => write!(f, "resolved package {name} does not have a valid Git source with a full 40-digit commit"),
        }
    }
}

impl Error for ProvenanceError {}

/// Resolve a unique Git package by its Cargo package name (not its crate alias).
pub fn dependency(name: &str) -> Result<DependencyProvenance<'static>, ProvenanceError> {
    from_lockfile(LOCKFILE, name)
}

pub fn interpreter() -> Result<DependencyProvenance<'static>, ProvenanceError> {
    dependency("bitcoin-scriptexec")
}

pub fn compiler() -> Result<DependencyProvenance<'static>, ProvenanceError> {
    dependency("bitcoin-script")
}

pub fn stack() -> Result<DependencyProvenance<'static>, ProvenanceError> {
    dependency("bitcoin-script-stack")
}

fn package_blocks(lockfile: &str) -> Vec<&str> {
    let mut blocks = Vec::new();
    let mut start = None;
    let mut offset = 0;
    for line in lockfile.split_inclusive('\n') {
        let header = line.trim();
        if header.starts_with('[') {
            if let Some(start) = start.take() {
                blocks.push(&lockfile[start..offset]);
            }
            if header == "[[package]]" {
                start = Some(offset + line.len());
            }
        }
        offset += line.len();
    }
    if let Some(start) = start {
        blocks.push(&lockfile[start..]);
    }
    blocks
}

fn field<'a>(block: &'a str, package: &str, key: &'static str) -> Result<&'a str, ProvenanceError> {
    let mut values = block.lines().filter_map(|line| {
        let (name, value) = line.split_once('=')?;
        (name.trim() == key).then_some(value.trim())
    });
    let raw = values.next().ok_or_else(|| ProvenanceError::MissingField {
        package: package.to_owned(),
        field: key,
    })?;
    let malformed = || ProvenanceError::MalformedField {
        package: package.to_owned(),
        field: key,
    };
    if values.next().is_some() {
        return Err(malformed());
    }
    let value = raw
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .ok_or_else(malformed)?;
    if value.is_empty()
        || value
            .chars()
            .any(|c| c == '"' || c == '\\' || c.is_control())
    {
        return Err(malformed());
    }
    Ok(value)
}

fn from_lockfile<'a>(
    lockfile: &'a str,
    name: &str,
) -> Result<DependencyProvenance<'a>, ProvenanceError> {
    let mut matching = None;
    for block in package_blocks(lockfile) {
        if field(block, name, "name")? == name && matching.replace(block).is_some() {
            return Err(ProvenanceError::DuplicatePackage(name.to_owned()));
        }
    }
    let block = matching.ok_or_else(|| ProvenanceError::MissingPackage(name.to_owned()))?;
    let version = field(block, name, "version")?;
    let source = field(block, name, "source")?;
    let git = source
        .strip_prefix("git+")
        .ok_or_else(|| ProvenanceError::NonGitSource(name.to_owned()))?;
    let invalid = || ProvenanceError::InvalidGitSource(name.to_owned());
    let (repository, commit) = git.rsplit_once('#').ok_or_else(invalid)?;
    let (scheme, location) = repository.split_once("://").ok_or_else(invalid)?;
    if scheme.is_empty()
        || !scheme.as_bytes()[0].is_ascii_alphabetic()
        || !scheme
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'-' | b'.'))
        || location.split('?').next().unwrap_or_default().is_empty()
        || repository.contains('#')
        || git.chars().any(char::is_whitespace)
        || commit.len() != 40
        || !commit.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(invalid());
    }
    Ok(DependencyProvenance {
        name: field(block, name, "name")?,
        version,
        source,
        commit,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIRST: &str = "1111111111111111111111111111111111111111";
    const SECOND: &str = "2222222222222222222222222222222222222222";

    fn package(name: &str, source: &str) -> String {
        format!("[[package]]\nname = \"{name}\"\nversion = \"0.4.0\"\nsource = \"{source}\"\n")
    }

    fn git_package(commit: &str) -> String {
        package(
            "example",
            &format!("git+https://example.org/repo?rev=release#{commit}"),
        )
    }

    #[test]
    fn resolves_build_time_dependencies() {
        for (resolved, name) in [
            (interpreter(), "bitcoin-scriptexec"),
            (compiler(), "bitcoin-script"),
            (stack(), "bitcoin-script-stack"),
        ] {
            let resolved = resolved.unwrap();
            assert_eq!(resolved.name, name);
            assert_eq!(resolved, dependency(name).unwrap());
            assert!(resolved.source.ends_with(&format!("#{}", resolved.commit)));
            assert!(!resolved.version.is_empty());
        }
    }

    #[test]
    fn uses_resolved_fragment_and_preserves_full_source() {
        let lock = git_package(FIRST);
        let resolved = from_lockfile(&lock, "example").unwrap();
        assert_eq!(
            resolved,
            DependencyProvenance {
                name: "example",
                version: "0.4.0",
                source: &format!("git+https://example.org/repo?rev=release#{FIRST}"),
                commit: FIRST,
            }
        );
        assert_eq!(
            from_lockfile(&lock.replace('\n', "\r\n"), "example")
                .unwrap()
                .commit,
            FIRST
        );
    }

    #[test]
    fn ignores_unused_patches_and_dependency_mentions() {
        let mut lock = package(
            "unrelated",
            &format!("git+https://example.org/repo#{FIRST}"),
        );
        lock.push_str("dependencies = [\n \"example\",\n]\n\n[[patch.unused]]\nname = \"example\"\nversion = \"0.4.0\"\n");
        assert_eq!(
            from_lockfile(&lock, "example"),
            Err(ProvenanceError::MissingPackage("example".into()))
        );
        lock.push_str(&git_package(SECOND));
        assert_eq!(from_lockfile(&lock, "example").unwrap().commit, SECOND);
        let used_then_unused =
            git_package(FIRST) + "[[patch.unused]]\nname = \"example\"\nversion = \"0.5.0\"\n";
        assert_eq!(
            from_lockfile(&used_then_unused, "example").unwrap().commit,
            FIRST
        );
    }

    #[test]
    fn rejects_duplicate_resolved_packages_even_with_different_versions() {
        for second in [
            git_package(FIRST),
            git_package(SECOND).replace("0.4.0", "0.5.0"),
        ] {
            let lock = git_package(FIRST) + &second;
            assert_eq!(
                from_lockfile(&lock, "example"),
                Err(ProvenanceError::DuplicatePackage("example".into()))
            );
        }
    }

    #[test]
    fn rejects_missing_malformed_and_duplicate_identity_fields() {
        let good = git_package(FIRST);
        for key in ["name", "version", "source"] {
            let line = good
                .lines()
                .find(|line| line.starts_with(&format!("{key} =")))
                .unwrap();
            let missing = good.replace(line, "");
            assert_eq!(
                from_lockfile(&missing, "example"),
                Err(ProvenanceError::MissingField {
                    package: "example".into(),
                    field: key
                })
            );
            for bad in [
                good.replace(line, &line.replace('"', "'")),
                good.clone() + line + "\n",
            ] {
                assert_eq!(
                    from_lockfile(&bad, "example"),
                    Err(ProvenanceError::MalformedField {
                        package: "example".into(),
                        field: key
                    })
                );
            }
        }
        for value in ["", "escaped\\n", "embedded\"quote"] {
            let bad = good.replace("version = \"0.4.0\"", &format!("version = \"{value}\""));
            assert!(matches!(
                from_lockfile(&bad, "example"),
                Err(ProvenanceError::MalformedField {
                    field: "version",
                    ..
                })
            ));
        }
    }

    #[test]
    fn rejects_non_git_and_malformed_resolved_commits() {
        let registry = package(
            "example",
            "registry+https://github.com/rust-lang/crates.io-index",
        );
        assert_eq!(
            from_lockfile(&registry, "example"),
            Err(ProvenanceError::NonGitSource("example".into()))
        );
        for source in [
            "git+https://example.org/repo".to_owned(),
            format!("git+#{FIRST}"),
            format!("git+not-a-url#{FIRST}"),
            format!("git+https://?rev=main#{FIRST}"),
            format!("git+https://example.org/repo#{FIRST}#{SECOND}"),
            format!("git+https://example.org/ repo#{FIRST}"),
            format!("git+https://example.org/repo?rev={FIRST}#main"),
            "git+https://example.org/repo#".to_owned(),
            format!("git+https://example.org/repo#{}", &FIRST[..39]),
            format!("git+https://example.org/repo#{}g", &FIRST[..39]),
        ] {
            assert_eq!(
                from_lockfile(&package("example", &source), "example"),
                Err(ProvenanceError::InvalidGitSource("example".into())),
                "{source}"
            );
        }
    }

    #[test]
    fn altered_lockfiles_change_only_the_parsed_identity() {
        let embedded = interpreter().unwrap();
        let old_lock = git_package(FIRST);
        let new_lock = old_lock.replace(FIRST, SECOND);
        let old = from_lockfile(&old_lock, "example").unwrap();
        let new = from_lockfile(&new_lock, "example").unwrap();
        assert_eq!(old.commit, FIRST);
        assert_eq!(new.commit, SECOND);
        assert_ne!(old.source, new.source);
        assert_eq!(interpreter().unwrap(), embedded);
    }
}
