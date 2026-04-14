//! MCP tool handlers.

pub mod accounts;
pub mod create_draft;
pub mod delete_message;
pub mod download_attachment;
pub mod expunge;
pub mod fetch_message;
pub mod flags;
pub mod folder_management;
pub mod labels;
pub mod list_attachments;
pub mod list_folders;
pub(crate) mod message_builder;
pub mod move_message;
pub(crate) mod part_walker;
pub mod search;
pub mod send_email;
