//! Magic-byte content-type sniffing and declared-vs-sniffed compatibility.

/// Sniff the content type of `body` from its leading magic bytes.
/// Returns the list of ALL matching signatures — a single match is
/// normal, multiple matches indicate a polyglot file.
pub(super) fn sniff_content_types(body: &[u8]) -> Vec<&'static str> {
    let signatures: &[(&[u8], &'static str)] = &[
        (b"\x89PNG\r\n\x1a\n", "image/png"),
        (b"\xff\xd8\xff", "image/jpeg"),
        (b"GIF87a", "image/gif"),
        (b"GIF89a", "image/gif"),
        (b"%PDF", "application/pdf"),
        (b"PK\x03\x04", "application/zip"),
        (b"MZ", "application/x-msdownload"),
        (b"\x7fELF", "application/x-elf"),
        (b"\xcf\xfa\xed\xfe", "application/x-mach-binary"),
        (b"\xfe\xed\xfa\xce", "application/x-mach-binary"),
        (b"\xfe\xed\xfa\xcf", "application/x-mach-binary"),
        (b"\xca\xfe\xba\xbe", "application/x-mach-binary"),
        (b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed"),
        (b"Rar!\x1a\x07\x00", "application/vnd.rar"),
        (b"Rar!\x1a\x07\x01\x00", "application/vnd.rar"),
        (
            b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
            "application/x-ole-storage",
        ),
    ];
    let mut matches: Vec<&'static str> = Vec::new();
    for (sig, label) in signatures {
        if body.starts_with(sig) && !matches.contains(label) {
            matches.push(label);
        }
    }
    matches
}

/// Return `true` if the declared content type is compatible with a
/// sniffed type. Exact (case-insensitive) matches are compatible.
/// `OpenXML` / `OpenDocument` declarations are compatible with a sniffed
/// `application/zip` (both are ZIP-based office formats).
///
/// `application/octet-stream` is NOT treated as a universal wildcard —
/// caller logic in `build_attachment_meta` decides whether an empty
/// sniff result makes `application/octet-stream` acceptable.
pub(super) fn content_types_compatible(declared: &str, sniffed: &str) -> bool {
    if declared.eq_ignore_ascii_case(sniffed) {
        return true;
    }
    if sniffed == "application/zip" {
        let dl = declared.to_ascii_lowercase();
        if dl.contains("openxmlformats") || dl.contains("opendocument") {
            return true;
        }
    }
    false
}
