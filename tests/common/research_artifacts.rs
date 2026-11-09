//! Compare current artifacts while retaining their historical source provenance.

/// Preserve the source-file inventory and every measured field. Only source
/// digest values may differ when shared files acquire unrelated code. Callers
/// must independently verify the stored hashes against the pinned Git tree.
pub fn reproduced_measurements(report: &serde_json::Value) -> serde_json::Value {
    let mut measurements = report.clone();
    let sources = measurements
        .get_mut("source_sha256")
        .unwrap()
        .as_object_mut()
        .unwrap();
    for (path, digest) in sources {
        let hex = digest.as_str().unwrap();
        assert!(
            hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid source digest for {path}"
        );
        *digest = serde_json::Value::Null;
    }
    measurements
}
