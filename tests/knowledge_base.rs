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
