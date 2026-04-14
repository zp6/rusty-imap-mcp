//! IMAP MIME part-ID computation, shared by attachment-walking handlers.
//!
//! RFC 3501 part numbering: for a multipart message the top-level parts
//! are "1", "2", "3", etc.; nested multipart sub-parts are "1.1", "1.2",
//! etc. For a non-multipart (single-part) message at the root, the sole
//! part is "1".

/// Compute the IMAP part ID for a leaf or message node.
/// Root-level nodes get `"1"`; nested nodes keep their prefix.
pub(crate) fn leaf_part_id(prefix: &str) -> String {
    if prefix.is_empty() {
        "1".to_string()
    } else {
        prefix.to_string()
    }
}

/// Compute the IMAP part ID for the `index`-th child of a multipart node.
/// Root-level children are `"1"`, `"2"`, etc.; nested children are
/// `"prefix.1"`, `"prefix.2"`, etc.
pub(crate) fn child_part_id(prefix: &str, index: usize) -> String {
    if prefix.is_empty() {
        index.to_string()
    } else {
        format!("{prefix}.{index}")
    }
}
