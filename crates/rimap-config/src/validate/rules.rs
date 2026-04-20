//! Domain rules: folder-list safety, SMTP requirement and encryption,
//! per-tool override resolution.

use std::collections::BTreeMap;
use std::str::FromStr;

use rimap_core::tool::ToolName;

use crate::error::ConfigError;
use crate::model::{SecurityConfig, SmtpConfig, SmtpEncryption, Verdict};

pub(super) fn validate_folder_safety(security: &SecurityConfig) -> Result<(), ConfigError> {
    let mut protected: Vec<String> = security
        .protected_folders
        .iter()
        .map(|f| utf7_imap::decode_utf7_imap(f.clone()).to_lowercase())
        .collect();
    protected.push("inbox".to_string());

    for folder in &security.expunge_folders {
        let norm = utf7_imap::decode_utf7_imap(folder.clone()).to_lowercase();
        if protected.contains(&norm) {
            return Err(ConfigError::ConflictingFolders {
                folder: folder.clone(),
            });
        }
    }
    Ok(())
}

pub(super) fn validate_smtp_required(
    security: &SecurityConfig,
    tool_overrides: &BTreeMap<ToolName, Verdict>,
    smtp: Option<&SmtpConfig>,
) -> Result<(), ConfigError> {
    let posture = security.posture;
    let send_email_base = rimap_core::base_allows(posture, ToolName::SendEmail);
    let send_email_effective = match tool_overrides.get(&ToolName::SendEmail) {
        Some(Verdict::Allow) => true,
        Some(Verdict::Deny) => false,
        None => send_email_base,
    };
    if send_email_effective && smtp.is_none() {
        return Err(ConfigError::SmtpRequired { posture });
    }
    Ok(())
}

pub(super) fn validate_smtp_encryption(smtp: Option<&SmtpConfig>) -> Result<(), ConfigError> {
    let Some(smtp) = smtp else {
        return Ok(());
    };
    if smtp.encryption == SmtpEncryption::None {
        let host = &smtp.host;
        let is_localhost = host == "localhost" || host == "127.0.0.1" || host == "::1";
        if !is_localhost {
            return Err(ConfigError::SmtpPlaintextDenied { host: host.clone() });
        }
    }
    Ok(())
}

pub(super) fn resolve_tool_overrides(
    security: &SecurityConfig,
) -> Result<BTreeMap<ToolName, Verdict>, ConfigError> {
    let mut out = BTreeMap::new();
    for (name, verdict) in &security.tools {
        let tool = ToolName::from_str(name)?;
        out.insert(tool, *verdict);
    }
    Ok(out)
}
