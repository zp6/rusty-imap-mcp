# `mail-parser 0.11` API reference for Sprint 4a Tasks 6–8

This is a drop-in reference for the implementer working on Tasks 6, 7, and 8 of the Sprint 4a plan. The plan was written assuming the `mail-parser 0.9.x` API and is WRONG about many method names and return types. **Use this doc as the source of truth for mail-parser 0.11 calls. Treat the plan's code blocks for Tasks 6–8 as structural templates only — the method names, return types, and helper shapes come from this reference.**

Pinned version: `mail-parser = "0.11"` (resolved 0.11.2). Confirmed via `cargo doc -p mail-parser --no-deps` on this branch.

## Top-level entrypoint

```rust
use mail_parser::{Message, MessageParser};

let message: Option<Message<'_>> = MessageParser::default().parse(raw);
```

`parse` returns `Option<Message>` — `None` on hard parse failure. Map to `ContentError::Malformed` with a reason string.

## `Message` accessors

All header accessors below are from `impl Message<'x>`:

```rust
// Address headers → Option<&Address<'x>>
message.from()       // Option<&Address>
message.to()         // Option<&Address>
message.cc()         // Option<&Address>
message.bcc()        // Option<&Address>
message.sender()     // Option<&Address>
message.reply_to()   // Option<&Address>

// Plain-string headers → Option<&str>
message.subject()    // Option<&str>
message.message_id() // Option<&str>  (angle brackets already stripped)

// Date → Option<&DateTime>
message.date()       // Option<&DateTime>

// Reference headers → &HeaderValue<'x>  (NOT Option — always present, may be Empty)
message.in_reply_to()     // &HeaderValue
message.references()      // &HeaderValue

// Mailing-list headers → &HeaderValue<'x>  (NOT Option)
message.list_id()
message.list_unsubscribe()
message.list_post()
message.list_archive()
message.list_help()
message.list_owner()
message.list_subscribe()

// Text bodies → Option<Cow<'x, str>>  (pre-decoded by mail-parser)
message.body_text(pos: usize)   // Option<Cow<'x, str>>
message.body_html(pos: usize)   // Option<Cow<'x, str>>
message.text_body_count()        // usize
message.html_body_count()        // usize
message.text_bodies()            // impl Iterator<Item = &MessagePart>
message.html_bodies()            // impl Iterator<Item = &MessagePart>

// Attachments
message.attachment(pos: u32)     // Option<&MessagePart<'x>>
message.attachment_count()       // usize
message.attachments()            // impl Iterator<Item = &MessagePart>

// MIME part lookup by index
message.part(pos: u32)           // Option<&MessagePart<'x>>

// Raw header access
message.headers()                // &[Header<'x>]
message.header(name: impl Into<HeaderName<'x>>)  // Option<&HeaderValue>
message.header_raw(name)         // Option<&str>
```

### Public fields on `Message`

```rust
pub struct Message<'x> {
    pub html_body: Vec<MessagePartId>,
    pub text_body: Vec<MessagePartId>,
    pub attachments: Vec<MessagePartId>,
    pub parts: Vec<MessagePart<'x>>,
    pub raw_message: Cow<'x, [u8]>,
}
```

`MessagePartId` is a type alias for **`u32`** (index into `parts`) in mail-parser 0.11.2 — the earlier docs said `usize` but `cargo doc` on the installed version confirms `u32`. Cast to `usize` at the indexing site: `message.parts.get(part_id as usize)`.

## `Address` enum

```rust
pub enum Address<'x> {
    List(Vec<Addr<'x>>),
    Group(Vec<Group<'x>>),
}

impl Address<'_> {
    pub fn first(&self) -> Option<&Addr<'x>>;           // first addr in first group/list
    pub fn last(&self) -> Option<&Addr<'x>>;
    pub fn as_list(&self) -> Option<&[Addr<'x>]>;       // None if it's a group
    pub fn as_group(&self) -> Option<&[Group<'x>]>;     // None if it's a list
    pub fn iter(&self) -> impl Iterator<Item = &Addr>;  // flattens list+group
    pub fn into_list(self) -> Vec<Addr<'x>>;
    pub fn into_group(self) -> Vec<Group<'x>>;
    pub fn contains(&self, addr: &str) -> bool;
}
```

**Important:** headers like `to`/`cc`/`bcc` may be EITHER a flat list OR grouped (e.g., `To: "Friends": alice@x, bob@x;`). Use `.iter()` to handle both cases uniformly.

## `Addr` struct

```rust
pub struct Addr<'x> {
    pub name: Option<Cow<'x, str>>,
    pub address: Option<Cow<'x, str>>,
}
```

Construct a display string like `"Name <email@host>"` or just `"email@host"` if no name.

## `Group` struct

```rust
pub struct Group<'x> {
    pub name: Option<Cow<'x, str>>,
    pub addresses: Vec<Addr<'x>>,
}
```

## `HeaderValue` enum

```rust
pub enum HeaderValue<'x> {
    Address(Address<'x>),
    Text(Cow<'x, str>),
    TextList(Vec<Cow<'x, str>>),
    DateTime(DateTime),
    ContentType(ContentType<'x>),
    Received(Box<Received<'x>>),
    Empty,
}

impl HeaderValue<'_> {
    pub fn is_empty(&self) -> bool;
    pub fn as_text(&self) -> Option<&str>;
    pub fn as_text_list(&self) -> Option<&[Cow<str>]>;  // or similar
    pub fn as_address(&self) -> Option<&Address>;
    pub fn as_datetime(&self) -> Option<&DateTime>;
    pub fn as_content_type(&self) -> Option<&ContentType>;
    pub fn as_received(&self) -> Option<&Received>;
    // Plus unwrap_* and into_* variants.
}
```

**Use `match` on variants for `in_reply_to()` / `references()` / `list_*()` outputs**, OR use `.as_text()` / `.as_text_list()` which return `Option<&str>` / `Option<&[Cow<str>]>`. `Empty` is returned when the header is absent — always handle it.

## `DateTime` struct

```rust
pub struct DateTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub tz_before_gmt: bool,
    pub tz_hour: u8,
    pub tz_minute: u8,
}

impl DateTime {
    pub fn to_timestamp(&self) -> i64;           // Unix seconds — use this for time::OffsetDateTime::from_unix_timestamp
    pub fn to_timestamp_local(&self) -> i64;
    pub fn to_rfc3339(&self) -> String;
    pub fn to_rfc822(&self) -> String;
    pub fn is_valid(&self) -> bool;
    pub fn from_timestamp(ts: i64) -> Self;
    pub fn to_timezone(&self, tz: i64) -> DateTime;
    pub fn day_of_week(&self) -> u8;
    pub fn julian_day(&self) -> i64;
    pub fn parse_rfc822(value: &str) -> Option<Self>;
    pub fn parse_rfc3339(value: &str) -> Option<Self>;
}
```

Use `dt.is_valid().then(|| dt.to_timestamp()).and_then(|ts| time::OffsetDateTime::from_unix_timestamp(ts).ok())` to convert into the workspace's `time::OffsetDateTime`.

## `MessagePart` struct

```rust
pub struct MessagePart<'x> {
    pub headers: Vec<Header<'x>>,
    pub is_encoding_problem: bool,
    pub body: PartType<'x>,          // <-- the content lives here
    pub encoding: Encoding,
    pub offset_header: u32,
    pub offset_body: u32,
    pub offset_end: u32,
}

impl MessagePart<'_> {
    pub fn headers(&self) -> &[Header<'x>];
    pub fn is_text(&self) -> bool;                // text/* MIME
    pub fn is_text_html(&self) -> bool;           // text/html specifically
    pub fn is_message(&self) -> bool;             // message/rfc822
    pub fn is_multipart(&self) -> bool;           // multipart/*
    pub fn is_binary(&self) -> bool;              // anything else
    pub fn is_empty(&self) -> bool;
    pub fn len(&self) -> usize;                   // body part length in bytes
    pub fn raw_len(&self) -> u32;                 // raw length including framing
    pub fn text_contents(&self) -> Option<&str>;  // text parts only
    pub fn message(&self) -> Option<&Message<'x>>; // nested message/rfc822
    pub fn sub_parts(&self) -> Option<&[MessagePartId]>; // children of a multipart
    pub fn raw_header_offset(&self) -> u32;
    pub fn raw_body_offset(&self) -> u32;
    pub fn raw_end_offset(&self) -> u32;
    pub fn into_owned(self) -> MessagePart<'static>;
}
```

**No `contents()` method, no `is_inline()` method, no `attachment_name()` on the struct directly.** Use:
- `PartType` match on `part.body` to get raw bytes (see below)
- `matches!(part.body, PartType::InlineBinary(_))` for inline detection
- `MimeHeaders::attachment_name(&part)` via the trait

## `PartType` enum

```rust
pub enum PartType<'x> {
    Text(Cow<'x, str>),        // any text/*
    Html(Cow<'x, str>),        // text/html
    Binary(Cow<'x, [u8]>),     // non-text, regular attachment
    InlineBinary(Cow<'x, [u8]>), // inline binary (e.g., inline image)
    Message(Message<'x>),      // nested message/rfc822
    Multipart(Vec<MessagePartId>), // children indices into Message.parts
}
```

### Extracting bytes from a part (for Task 8's attachments)

```rust
fn part_bytes(part: &MessagePart<'_>) -> &[u8] {
    match &part.body {
        PartType::Text(s) | PartType::Html(s) => s.as_bytes(),
        PartType::Binary(b) | PartType::InlineBinary(b) => b.as_ref(),
        PartType::Message(_) | PartType::Multipart(_) => &[],
    }
}
```

### Inline detection (for Task 8)

```rust
fn is_inline(part: &MessagePart<'_>) -> bool {
    // Two ways — either PartType variant, or Content-Disposition header.
    // Prefer the PartType variant because it's what mail-parser actually
    // parsed; if we need to honor an explicit "attachment" disposition
    // override, also check the ContentDisposition.
    matches!(part.body, PartType::InlineBinary(_))
        || part.content_disposition()
            .map(|cd| cd.is_inline())
            .unwrap_or(false)
}
```

## `MimeHeaders` trait

Implemented by both `Message` and `MessagePart`. All methods return `Option<...>`:

```rust
pub trait MimeHeaders<'x> {
    fn content_description(&self) -> Option<&str>;
    fn content_disposition(&self) -> Option<&ContentType<'_>>;  // YES, a ContentType
    fn content_id(&self) -> Option<&str>;
    fn content_transfer_encoding(&self) -> Option<&str>;
    fn content_type(&self) -> Option<&ContentType<'_>>;
    fn content_language(&self) -> &HeaderValue<'_>;
    fn content_location(&self) -> Option<&str>;

    // Provided:
    fn attachment_name(&self) -> Option<&str>;
    fn is_content_type(&self, type_: &str, subtype: &str) -> bool;
}
```

## `ContentType` struct

```rust
pub struct ContentType<'x> {
    pub c_type: Cow<'x, str>,
    pub c_subtype: Option<Cow<'x, str>>,
    pub attributes: Option<Vec<Attribute<'x>>>,
}

impl ContentType<'_> {
    pub fn ctype(&self) -> &str;              // primary type, e.g. "image"
    pub fn subtype(&self) -> Option<&str>;    // subtype, e.g. "png"
    pub fn attribute(&self, name: &str) -> Option<&str>;   // e.g. "charset"
    pub fn has_attribute(&self, name: &str) -> bool;
    pub fn attributes(&self) -> Option<&[Attribute<'x>]>;
    pub fn is_attachment(&self) -> bool;      // only on Content-Disposition
    pub fn is_inline(&self) -> bool;          // only on Content-Disposition
}
```

Compose a `"type/subtype"` string:
```rust
fn content_type_string(ct: &mail_parser::ContentType<'_>) -> String {
    match ct.subtype() {
        Some(sub) => format!("{}/{}", ct.ctype(), sub),
        None => ct.ctype().to_string(),
    }
}
```

## Adapted code templates

### Task 6 — header extraction against 0.11

```rust
use mail_parser::{Address, HeaderValue, Message, MessageParser};
use time::OffsetDateTime;

use crate::error::ContentError;
use crate::output::{
    Content, ContentMeta, MailingListInfo, SecurityWarning, Untrusted, WarningCode,
};
use crate::unicode;

pub fn parse_message(raw: &[u8]) -> Result<Content, ContentError> {
    let original_size_bytes = raw.len() as u64;
    let mut warnings: Vec<SecurityWarning> = Vec::new();
    let scrubbed = scrub_header_smuggling(raw, &mut warnings);

    let message = MessageParser::default()
        .parse(&scrubbed)
        .ok_or_else(|| ContentError::Malformed {
            reason: "mail-parser rejected byte stream".to_string(),
        })?;

    enforce_header_count(&message, &mut warnings)?;

    let meta = extract_meta(&message, original_size_bytes, &mut warnings);

    Ok(Content {
        meta,
        untrusted: Untrusted::default(), // Task 7 wires bodies
        security_warnings: warnings,
    })
}

fn enforce_header_count(
    message: &Message<'_>,
    warnings: &mut Vec<SecurityWarning>,
) -> Result<(), ContentError> {
    let header_count = message.headers().len();
    if header_count > MAX_HEADER_COUNT {
        warnings.push(SecurityWarning {
            code: WarningCode::ParseHeaderCountExceeded,
            detail: Some(format!("count={header_count} limit={MAX_HEADER_COUNT}")),
            location: Some("headers".to_string()),
        });
        return Err(ContentError::LimitExceeded {
            kind: "header_count",
            limit: MAX_HEADER_COUNT,
        });
    }
    Ok(())
}

fn extract_meta(
    message: &Message<'_>,
    original_size_bytes: u64,
    warnings: &mut Vec<SecurityWarning>,
) -> ContentMeta {
    let from = first_address_string(message.from(), "header:from", warnings);
    let to = address_strings(message.to(), "header:to", warnings);
    let cc = address_strings(message.cc(), "header:cc", warnings);
    let subject = sanitize_opt_str(message.subject(), "header:subject", warnings);
    let date = message.date().and_then(convert_datetime);
    let message_id = sanitize_opt_str(message.message_id(), "header:message_id", warnings);
    let in_reply_to = header_value_first_text(
        message.in_reply_to(),
        "header:in_reply_to",
        warnings,
    );
    let references = header_value_all_text(
        message.references(),
        "header:references",
        warnings,
    );

    ContentMeta {
        from,
        to,
        cc,
        subject,
        date,
        message_id,
        in_reply_to,
        references,
        mailing_list: None,          // Task 8
        attachments: Vec::new(),     // Task 8
        original_size_bytes,
        body_truncated: false,       // Task 7
    }
}

fn sanitize_opt_str(
    value: Option<&str>,
    location: &str,
    warnings: &mut Vec<SecurityWarning>,
) -> Option<String> {
    let value = value?;
    let (text, mut new_warnings) =
        unicode::sanitize(value.as_bytes(), Some("utf-8"), MAX_HEADER_BYTES, location);
    warnings.append(&mut new_warnings);
    Some(text)
}

/// Flatten an `Address` (list or group) into a sequence of display
/// strings and sanitize each one.
fn address_strings(
    address: Option<&Address<'_>>,
    location: &str,
    warnings: &mut Vec<SecurityWarning>,
) -> Vec<String> {
    let Some(address) = address else {
        return Vec::new();
    };
    address
        .iter()
        .map(|addr| format_addr(addr))
        .map(|raw| {
            let (text, mut new_warnings) = unicode::sanitize(
                raw.as_bytes(),
                Some("utf-8"),
                MAX_HEADER_BYTES,
                location,
            );
            warnings.append(&mut new_warnings);
            text
        })
        .collect()
}

fn first_address_string(
    address: Option<&Address<'_>>,
    location: &str,
    warnings: &mut Vec<SecurityWarning>,
) -> Option<String> {
    let raw = format_addr(address?.first()?);
    let (text, mut new_warnings) =
        unicode::sanitize(raw.as_bytes(), Some("utf-8"), MAX_HEADER_BYTES, location);
    warnings.append(&mut new_warnings);
    Some(text)
}

fn format_addr(addr: &mail_parser::Addr<'_>) -> String {
    let email = addr.address.as_deref().unwrap_or("");
    match addr.name.as_deref() {
        Some(name) if !name.is_empty() => format!("{name} <{email}>"),
        _ => email.to_string(),
    }
}

fn header_value_first_text(
    value: &HeaderValue<'_>,
    location: &str,
    warnings: &mut Vec<SecurityWarning>,
) -> Option<String> {
    let raw = match value {
        HeaderValue::Text(s) => s.as_ref().to_string(),
        HeaderValue::TextList(list) => list.first()?.as_ref().to_string(),
        _ => return None,
    };
    let (text, mut new_warnings) =
        unicode::sanitize(raw.as_bytes(), Some("utf-8"), MAX_HEADER_BYTES, location);
    warnings.append(&mut new_warnings);
    Some(text)
}

fn header_value_all_text(
    value: &HeaderValue<'_>,
    location: &str,
    warnings: &mut Vec<SecurityWarning>,
) -> Vec<String> {
    let raws: Vec<String> = match value {
        HeaderValue::Text(s) => vec![s.as_ref().to_string()],
        HeaderValue::TextList(list) => list.iter().map(|s| s.as_ref().to_string()).collect(),
        _ => return Vec::new(),
    };
    raws.into_iter()
        .map(|raw| {
            let (text, mut new_warnings) = unicode::sanitize(
                raw.as_bytes(),
                Some("utf-8"),
                MAX_HEADER_BYTES,
                location,
            );
            warnings.append(&mut new_warnings);
            text
        })
        .collect()
}

fn convert_datetime(dt: &mail_parser::DateTime) -> Option<OffsetDateTime> {
    if !dt.is_valid() {
        return None;
    }
    OffsetDateTime::from_unix_timestamp(dt.to_timestamp()).ok()
}
```

### Task 7 — body extraction against 0.11

```rust
use mail_parser::PartType;

fn extract_bodies(
    message: &Message<'_>,
    warnings: &mut Vec<SecurityWarning>,
) -> Result<BodyExtraction, ContentError> {
    let part_count = message.parts.len();
    if part_count > MAX_MIME_PARTS {
        warnings.push(SecurityWarning {
            code: WarningCode::ParseMimePartCountExceeded,
            detail: Some(format!("count={part_count} limit={MAX_MIME_PARTS}")),
            location: Some("mime".to_string()),
        });
        return Err(ContentError::LimitExceeded {
            kind: "mime_parts",
            limit: MAX_MIME_PARTS,
        });
    }

    check_mime_depth(message, warnings)?;

    let mut primary_text: Option<String> = None;
    let mut alternates: Vec<String> = Vec::new();
    let mut body_truncated = false;

    // Walk text_body indices — this is the ordered list of text/*
    // parts mail-parser identifies as body (excluding attachments
    // and nested message/rfc822 bodies).
    for (idx, &part_id) in message.text_body.iter().enumerate() {
        let Some(part) = message.parts.get(part_id as usize) else {
            continue;
        };
        // Skip nested rfc822 — their text is another message's body.
        if matches!(part.body, PartType::Message(_)) {
            continue;
        }
        let raw_bytes = match &part.body {
            PartType::Text(s) | PartType::Html(s) => s.as_bytes(),
            _ => continue,
        };
        if raw_bytes.len() > MAX_BODY_BYTES {
            body_truncated = true;
            warnings.push(SecurityWarning {
                code: WarningCode::ParseBodyTruncated,
                detail: Some(format!(
                    "original={} limit={}",
                    raw_bytes.len(),
                    MAX_BODY_BYTES
                )),
                location: Some(format!("body:text[{idx}]")),
            });
        }
        let location = format!("body:text[{idx}]");
        let charset = part
            .content_type()
            .and_then(|ct| ct.attribute("charset"))
            .map(str::to_string);
        let (text, mut new_warnings) =
            unicode::sanitize(raw_bytes, charset.as_deref(), MAX_BODY_BYTES, &location);
        warnings.append(&mut new_warnings);

        if primary_text.is_none() {
            primary_text = Some(text);
        } else {
            alternates.push(text);
        }
    }

    Ok(BodyExtraction {
        primary_text: primary_text.unwrap_or_default(),
        alternates,
        body_truncated,
    })
}

fn check_mime_depth(
    message: &Message<'_>,
    warnings: &mut Vec<SecurityWarning>,
) -> Result<(), ContentError> {
    let depth = compute_max_depth(message);
    if depth > MAX_MIME_DEPTH {
        warnings.push(SecurityWarning {
            code: WarningCode::ParseMimeDepthExceeded,
            detail: Some(format!("depth={depth} limit={MAX_MIME_DEPTH}")),
            location: Some("mime".to_string()),
        });
        return Err(ContentError::LimitExceeded {
            kind: "mime_depth",
            limit: MAX_MIME_DEPTH,
        });
    }
    Ok(())
}

/// Walk the MIME tree from part 0 and return the maximum depth.
fn compute_max_depth(message: &Message<'_>) -> usize {
    depth_recursive(message, 0, 1)
}

fn depth_recursive(message: &Message<'_>, part_id: usize, current: usize) -> usize {
    let Some(part) = message.parts.get(part_id) else {
        return current;
    };
    match &part.body {
        PartType::Multipart(child_ids) => child_ids
            .iter()
            .map(|&child_id| depth_recursive(message, child_id as usize, current + 1))
            .max()
            .unwrap_or(current),
        PartType::Message(nested) => {
            // Nested rfc822 bumps depth by one level for the nested
            // container itself. Do not recurse into nested.parts — the
            // nested message is its own parse tree and we treat its
            // bodies as attachment metadata only.
            current + 1
        }
        _ => current,
    }
}

#[derive(Debug)]
struct BodyExtraction {
    primary_text: String,
    alternates: Vec<String>,
    body_truncated: bool,
}
```

Note: `MessagePartId` is `u32` in 0.11.2. `message.text_body: Vec<MessagePartId>` requires an `as usize` cast when indexing into `message.parts`. The code sample above has been updated.

### Task 8 — attachments, magic-byte sniff, mailing list against 0.11

```rust
use mail_parser::MimeHeaders as _;

fn extract_attachments(
    message: &Message<'_>,
    warnings: &mut Vec<SecurityWarning>,
) -> Vec<crate::output::AttachmentMeta> {
    let mut out = Vec::new();
    for (idx, part_id) in message.attachments.iter().enumerate() {
        let Some(part) = message.parts.get(*part_id as usize) else {
            continue;
        };
        let declared_ct = part
            .content_type()
            .map(content_type_string)
            .unwrap_or_else(|| "application/octet-stream".to_string());

        let body = part_bytes(part);

        if let Some(sniffed_ct) = sniff_content_type(body) {
            if !content_types_compatible(&declared_ct, sniffed_ct) {
                warnings.push(SecurityWarning {
                    code: WarningCode::ParseMimeTypeMismatch,
                    detail: Some(format!("declared={declared_ct} sniffed={sniffed_ct}")),
                    location: Some(format!("attachment[{idx}]")),
                });
            }
        }

        let filename = part.attachment_name().map(|name| {
            let (text, mut ws) = unicode::sanitize(
                name.as_bytes(),
                Some("utf-8"),
                MAX_HEADER_BYTES,
                &format!("attachment[{idx}]:filename"),
            );
            warnings.append(&mut ws);
            text
        });

        let content_id = part.content_id().map(|id| {
            let (text, mut ws) = unicode::sanitize(
                id.as_bytes(),
                Some("utf-8"),
                MAX_HEADER_BYTES,
                &format!("attachment[{idx}]:content_id"),
            );
            warnings.append(&mut ws);
            text
        });

        let (sanitized_ct, mut ct_ws) = unicode::sanitize(
            declared_ct.as_bytes(),
            Some("utf-8"),
            MAX_HEADER_BYTES,
            &format!("attachment[{idx}]:content_type"),
        );
        warnings.append(&mut ct_ws);

        out.push(crate::output::AttachmentMeta {
            filename,
            content_type: sanitized_ct,
            size_bytes: body.len() as u64,
            content_id,
            is_inline: is_inline(part),
        });
    }
    out
}

fn part_bytes<'a>(part: &'a mail_parser::MessagePart<'_>) -> &'a [u8] {
    match &part.body {
        PartType::Text(s) | PartType::Html(s) => s.as_bytes(),
        PartType::Binary(b) | PartType::InlineBinary(b) => b.as_ref(),
        PartType::Message(_) | PartType::Multipart(_) => &[],
    }
}

fn is_inline(part: &mail_parser::MessagePart<'_>) -> bool {
    matches!(part.body, PartType::InlineBinary(_))
        || part
            .content_disposition()
            .map(|cd| cd.is_inline())
            .unwrap_or(false)
}

fn content_type_string(ct: &mail_parser::ContentType<'_>) -> String {
    match ct.subtype() {
        Some(sub) => format!("{}/{}", ct.ctype(), sub),
        None => ct.ctype().to_string(),
    }
}

fn extract_mailing_list(
    message: &Message<'_>,
    warnings: &mut Vec<SecurityWarning>,
) -> Option<MailingListInfo> {
    let list_id = sanitize_header_value(
        message.list_id(),
        "header:list_id",
        warnings,
    );
    let list_unsubscribe = sanitize_header_value(
        message.list_unsubscribe(),
        "header:list_unsubscribe",
        warnings,
    );
    let list_post = sanitize_header_value(
        message.list_post(),
        "header:list_post",
        warnings,
    );

    if list_id.is_none() && list_unsubscribe.is_none() && list_post.is_none() {
        return None;
    }
    Some(MailingListInfo {
        list_id,
        list_unsubscribe,
        list_post,
    })
}

fn sanitize_header_value(
    value: &HeaderValue<'_>,
    location: &str,
    warnings: &mut Vec<SecurityWarning>,
) -> Option<String> {
    let raw = match value {
        HeaderValue::Text(s) => s.as_ref().to_string(),
        HeaderValue::TextList(list) => list
            .iter()
            .map(|s| s.as_ref())
            .collect::<Vec<_>>()
            .join(", "),
        // IMPORTANT: mail-parser 0.11 routes `List-ID`, `List-Unsubscribe`,
        // `List-Post`, etc. through `parse_address()`, so they come back as
        // `HeaderValue::Address` — NOT `Text`. Flatten the address(es)
        // through the same `format_addr` path used for From/To/Cc.
        HeaderValue::Address(address) => address
            .iter()
            .map(format_addr)
            .collect::<Vec<_>>()
            .join(", "),
        HeaderValue::Empty => return None,
        _ => return None,
    };
    if raw.is_empty() {
        return None;
    }
    let (text, mut new_warnings) =
        unicode::sanitize(raw.as_bytes(), Some("utf-8"), MAX_HEADER_BYTES, location);
    warnings.append(&mut new_warnings);
    Some(text)
}
```

`sniff_content_type` and `content_types_compatible` from the plan are unchanged — they don't touch mail-parser.

## What the plan got wrong (and this doc corrects)

- Plan said `HeaderValue::Address(address)` matching to extract `from`/`to`/etc. 0.11 returns `Option<&Address>` directly from `message.from()`.
- Plan said `mail_parser::DateTime::to_timestamp` after querying via `message.date()`. The method does exist — but `message.date()` returns `Option<&DateTime>`, not `Option<DateTime>`.
- Plan said `message.in_reply_to()` returns an `Option<&HeaderValue>`. 0.11 returns `&HeaderValue` directly (never `Option`).
- Plan said `message.text_bodies()` yields `&MessagePart` — correct, but the plan's `part.contents()` for raw bytes does NOT exist. Use `PartType::Text(cow).as_bytes()` or the `part_bytes` helper in this doc.
- Plan said `attachment.is_inline()`. This method does NOT exist on `MessagePart`. Use the `is_inline` helper in this doc (checks `PartType::InlineBinary` variant or Content-Disposition).
- Plan said `attachment.contents()`. This method does NOT exist. Use the `part_bytes` helper.
- Plan said `attachment.content_type()` etc. on `MessagePart` — correct, via the `MimeHeaders` trait import (`use mail_parser::MimeHeaders as _;`).
- Plan said `ct.ctype()` and `ct.subtype()` — correct. Use `content_type_string` helper to compose.
- Plan used a custom `recursive_depth` that matched `PartType::Multipart(children)` where `children` was `Vec<usize>`. In 0.11 it's `Vec<MessagePartId>` which is a type alias for `usize`, so the match still works. But also handle `PartType::Message(nested)` as +1 depth for the nested container.

## Handoff note for Task 13

When Task 13 writes the Sprint 4b handoff doc, record that:
- `unicode-properties` is declared but unused in Sprint 4a (Task 4 note). Sprint 4b's lookalike module will consume it.
- Mail-parser API reference at `docs/superpowers/plans/2026-04-08-sprint-4a-mail-parser-0.11-api.md` should be consulted for any 4b work that touches the parse tree.
