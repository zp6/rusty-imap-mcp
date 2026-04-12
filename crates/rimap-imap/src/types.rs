//! Public types for `rimap-imap`. These are the IMAP-shaped data the read
//! ops return — RFC-5322 / MIME parsing belongs to `rimap-content` (Sprint 4).

use std::num::NonZeroU32;

/// IMAP UID. Always non-zero per RFC 3501 §2.3.1.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Uid(NonZeroU32);

impl Uid {
    /// Construct from a raw integer. Returns `None` for `0`.
    #[must_use]
    pub fn new(n: u32) -> Option<Self> {
        NonZeroU32::new(n).map(Self)
    }

    /// Underlying integer.
    #[must_use]
    pub fn get(self) -> u32 {
        self.0.get()
    }
}

/// Opaque RFC 5322 `Message-ID` header value, as raw bytes (no decoding).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageId(Vec<u8>);

impl MessageId {
    /// Construct from raw bytes.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Underlying raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// IMAP `LIST` response entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Folder {
    /// Folder name (mailbox path) as the server reported it. Modified UTF-7
    /// decoding is left to the caller / Sprint 4.
    pub name: String,
    /// Folder attribute flags (`\Noinferiors`, `\Marked`, etc.).
    pub attributes: Vec<String>,
    /// Hierarchy delimiter, if the server reported one.
    pub delimiter: Option<char>,
}

/// Bitflags-style selection for `STATUS` items.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "bitflags-style selector; each field is independent"
)]
pub struct StatusItems {
    /// Include `MESSAGES` (total count).
    pub messages: bool,
    /// Include `RECENT`.
    pub recent: bool,
    /// Include `UIDNEXT`.
    pub uid_next: bool,
    /// Include `UIDVALIDITY`.
    pub uid_validity: bool,
    /// Include `UNSEEN`.
    pub unseen: bool,
}

impl StatusItems {
    /// All items selected.
    #[must_use]
    pub fn all() -> Self {
        Self {
            messages: true,
            recent: true,
            uid_next: true,
            uid_validity: true,
            unseen: true,
        }
    }
}

/// Result of a `STATUS` command. Fields are populated only when requested.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FolderStatus {
    /// `MESSAGES`.
    pub messages: Option<u32>,
    /// `RECENT`.
    pub recent: Option<u32>,
    /// `UIDNEXT`.
    pub uid_next: Option<u32>,
    /// `UIDVALIDITY`.
    pub uid_validity: Option<u32>,
    /// `UNSEEN`.
    pub unseen: Option<u32>,
}

/// Result of a `SELECT` or `EXAMINE` command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedFolder {
    /// Mailbox name.
    pub name: String,
    /// `EXISTS` count.
    pub exists: u32,
    /// `RECENT` count.
    pub recent: u32,
    /// `UIDVALIDITY`.
    pub uid_validity: u32,
    /// `UIDNEXT`.
    pub uid_next: Option<u32>,
    /// `READ-ONLY` if `EXAMINE`, otherwise `READ-WRITE`.
    pub read_only: bool,
}

/// IMAP message flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Flag {
    /// `\Seen`.
    Seen,
    /// `\Answered`.
    Answered,
    /// `\Flagged`.
    Flagged,
    /// `\Deleted`.
    Deleted,
    /// `\Draft`.
    Draft,
    /// `\Recent` (RFC 3501 only; deprecated in RFC 9051).
    Recent,
    /// Server-specific keyword (anything not in the canonical list above).
    Keyword(String),
}

/// Whether to add or remove flags in a STORE command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlagAction {
    /// `+FLAGS` — add the given flags.
    Add,
    /// `-FLAGS` — remove the given flags.
    Remove,
}

/// IMAP `ENVELOPE` response. Header values stay raw bytes — RFC 2047 decoding
/// is Sprint 4's responsibility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// `Date` header, raw.
    pub date: Option<Vec<u8>>,
    /// `Subject` header, raw.
    pub subject_raw: Option<Vec<u8>>,
    /// `From` addresses, raw.
    pub from: Vec<Address>,
    /// `Sender` addresses, raw.
    pub sender: Vec<Address>,
    /// `Reply-To` addresses, raw.
    pub reply_to: Vec<Address>,
    /// `To` addresses, raw.
    pub to: Vec<Address>,
    /// `Cc` addresses, raw.
    pub cc: Vec<Address>,
    /// `Bcc` addresses, raw.
    pub bcc: Vec<Address>,
    /// `In-Reply-To` header, raw.
    pub in_reply_to: Option<Vec<u8>>,
    /// `Message-ID` header, raw.
    pub message_id: Option<MessageId>,
}

/// IMAP envelope address. Raw bytes; no charset decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    /// Personal name (`name`), raw.
    pub name: Option<Vec<u8>>,
    /// Source route (`adl`), raw.
    pub adl: Option<Vec<u8>>,
    /// Mailbox local part, raw.
    pub mailbox: Option<Vec<u8>>,
    /// Host part, raw.
    pub host: Option<Vec<u8>>,
}

/// IMAP `BODYSTRUCTURE` recursive type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyStructure {
    /// A single-part body.
    Single {
        /// MIME type (`text`, `image`, …).
        mime_type: String,
        /// MIME subtype (`plain`, `jpeg`, …).
        mime_subtype: String,
        /// MIME content-type parameters.
        params: Vec<(String, String)>,
        /// Transfer encoding (`7bit`, `base64`, …).
        encoding: String,
        /// Octet count.
        size: u32,
    },
    /// A `multipart/*` body.
    Multipart {
        /// Multipart subtype (`mixed`, `alternative`, …).
        subtype: String,
        /// Constituent parts.
        parts: Vec<BodyStructure>,
    },
    /// A `message/rfc822` (or similar `message/*`) body containing a fully
    /// nested embedded message. The nested `body` is the BODYSTRUCTURE of
    /// the embedded message; walk it like any other tree.
    Message {
        /// MIME subtype (typically `"rfc822"`).
        mime_subtype: String,
        /// The embedded message's body structure.
        body: Box<BodyStructure>,
    },
}

/// SEARCH query — either a structured builder or a raw passthrough.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SearchQuery {
    /// Typed query built via `StructuredQuery`. This is the path all
    /// untrusted input (agent prompts, MCP tool arguments, HTTP requests)
    /// MUST take — `StructuredQuery`'s field builders apply the necessary
    /// RFC 3501 quoting and reject CR/LF/NUL bytes.
    Structured(StructuredQuery),
    /// Raw IMAP SEARCH key string, forwarded verbatim to `UID SEARCH`
    /// without further validation.
    ///
    /// # Safety boundary
    ///
    /// Callers are entirely responsible for RFC 3501 compliance. This
    /// variant bypasses async-imap's `validate_str` — embedded CR, LF, or
    /// NUL bytes will terminate the tagged command line and inject a
    /// follow-on command.
    ///
    /// Untrusted input (anything reachable from an agent prompt or an
    /// external API) MUST NOT be routed through this variant. Use
    /// [`SearchQuery::Structured`] instead. This escape hatch exists for
    /// integration tests and internal tooling where the caller controls
    /// the key.
    Raw(String),
}

/// Structured SEARCH builder. Empty builder = `ALL`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StructuredQuery {
    /// Match `FROM` substring.
    pub from: Option<String>,
    /// Match `TO` substring.
    pub to: Option<String>,
    /// Match `SUBJECT` substring.
    pub subject: Option<String>,
    /// `SINCE` (inclusive lower bound by INTERNALDATE).
    pub since: Option<::time::Date>,
    /// `BEFORE` (exclusive upper bound by INTERNALDATE).
    pub before: Option<::time::Date>,
    /// Restrict to messages with `\Seen`.
    pub seen: Option<bool>,
    /// Restrict to messages with attachments (`HAS_ATTACHMENT` heuristic;
    /// emitted as `BODY "Content-Disposition: attachment"`).
    pub has_attachment: bool,
}

/// FETCH item selection. `ENVELOPE`, `BODYSTRUCTURE`, `UID`, `FLAGS`, `SIZE`.
/// `BODY[]` has its own dedicated method (`Connection::fetch_body`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "bitflags-style selector; each field is independent"
)]
pub struct FetchSpec {
    /// Include `ENVELOPE`.
    pub envelope: bool,
    /// Include `BODYSTRUCTURE`.
    pub bodystructure: bool,
    /// Include `UID`.
    pub uid: bool,
    /// Include `FLAGS`.
    pub flags: bool,
    /// Include `RFC822.SIZE`.
    pub size: bool,
}

/// One message returned by a `fetch` call. Only the fields requested in the
/// `FetchSpec` are populated; the rest are `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchedMessage {
    /// Message UID (always present — IMAP servers always return UID for UID FETCH).
    pub uid: Uid,
    /// `ENVELOPE` if requested.
    pub envelope: Option<Envelope>,
    /// `BODYSTRUCTURE` if requested.
    pub bodystructure: Option<BodyStructure>,
    /// `FLAGS` if requested.
    pub flags: Option<Vec<Flag>>,
    /// `RFC822.SIZE` if requested.
    pub size: Option<u32>,
}
