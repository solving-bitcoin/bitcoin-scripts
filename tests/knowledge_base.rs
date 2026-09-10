//! Structural validation for the agent-facing primitive knowledge base.

use std::{path::Path, process::Command};

#[test]
fn knowledge_catalog_is_valid() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let status = Command::new("python3")
        .args(["tools/kb.py", "validate"])
        .current_dir(root)
        .status()
        .expect("python3 is required to validate knowledge/catalog.json");
    assert!(status.success(), "knowledge-base validation failed");
}

#[test]
fn knowledge_configuration_qualifiers_are_respected() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let status = Command::new("python3")
        .args([
            "-m",
            "unittest",
            "discover",
            "-s",
            "tools",
            "-p",
            "test_kb.py",
        ])
        .current_dir(root)
        .status()
        .expect("python3 is required to test knowledge-base queries");
    assert!(status.success(), "knowledge-base query regression failed");
}
