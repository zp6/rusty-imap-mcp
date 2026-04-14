//! MCP tool handlers.

pub mod accounts;
pub mod create_draft;
pub mod delete_message;
pub mod download_attachment;
pub mod expunge;
pub mod fetch_message;
pub mod flags;
pub mod folder_mgmt;
pub mod labels;
pub mod list_attachments;
pub mod list_folders;
pub(crate) mod message_builder;
pub(crate) mod mime_part_id;
pub mod move_message;
pub mod search;
pub mod send_email;
