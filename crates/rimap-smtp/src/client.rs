//! `SmtpClient` — one-shot SMTP send via `lettre`.

use std::time::Duration;

use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Tokio1Executor};
use rimap_config::model::{SmtpConfig, SmtpEncryption};

use crate::error::SmtpError;

/// Addressing envelope for [`SmtpClient::send_raw`], expressed with
/// plain string addresses so callers do not need to depend on
/// `lettre`'s address types. Addresses are parsed here at the crate
/// boundary and surface as `SmtpError::Rejected` on malformed input.
#[derive(Debug, Clone)]
pub struct SendEnvelope {
    /// Sender address (`MAIL FROM`).
    pub from: String,
    /// Recipient addresses (`RCPT TO`). All of To/Cc/Bcc collapsed.
    pub to: Vec<String>,
}

/// SMTP client built from config. Each `send()` call opens a fresh
/// connection — no persistent session or connection pool.
pub struct SmtpClient {
    transport: AsyncSmtpTransport<Tokio1Executor>,
}

impl SmtpClient {
    /// Build from validated SMTP config and a resolved password.
    ///
    /// # Errors
    ///
    /// Returns `SmtpError::Connection` if the transport cannot be built.
    pub fn new(config: &SmtpConfig, password: &str) -> Result<Self, SmtpError> {
        let creds = Credentials::new(config.username.clone(), password.to_string());
        let timeout = Duration::from_secs(u64::from(config.command_timeout_seconds));

        let builder = match config.encryption {
            SmtpEncryption::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(&config.host)
                .map_err(SmtpError::Connection)?
                .port(config.port),
            SmtpEncryption::Starttls => {
                AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.host)
                    .map_err(SmtpError::Connection)?
                    .port(config.port)
            }
            SmtpEncryption::None => {
                AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&config.host)
                    .port(config.port)
            }
        };

        let transport = builder.credentials(creds).timeout(Some(timeout)).build();

        Ok(Self { transport })
    }

    /// Send a pre-built message via SMTP.
    ///
    /// Returns the SMTP response string on success (typically "250 OK").
    ///
    /// # Errors
    ///
    /// Returns `SmtpError` variants for auth, TLS, rejection, timeout,
    /// or transport failures. SMTP server banners and detailed rejection
    /// reasons are captured in the error but should NOT be forwarded to
    /// MCP clients — log them to audit only.
    pub async fn send(&self, message: &lettre::Message) -> Result<String, SmtpError> {
        let response = self
            .transport
            .send(message.clone())
            .await
            .map_err(classify_smtp_error)?;
        Ok(format_response(&response))
    }

    /// Send raw RFC 5322 bytes with an explicit envelope.
    ///
    /// Use this when the message is already serialized (e.g. from
    /// `mail-builder`) and constructing a `lettre::Message` is not
    /// practical.
    ///
    /// # Errors
    ///
    /// Returns `SmtpError` variants for auth, TLS, rejection, timeout,
    /// or transport failures.
    pub async fn send_raw(&self, envelope: &SendEnvelope, raw: &[u8]) -> Result<String, SmtpError> {
        let lettre_env = build_lettre_envelope(envelope)?;
        let response = self
            .transport
            .send_raw(&lettre_env, raw)
            .await
            .map_err(classify_smtp_error)?;
        Ok(format_response(&response))
    }
}

/// Parse the string-keyed [`SendEnvelope`] into a `lettre` envelope.
/// Malformed addresses or the empty-recipient case surface as
/// `SmtpError::Rejected` so the error taxonomy stays inside the crate.
fn build_lettre_envelope(env: &SendEnvelope) -> Result<lettre::address::Envelope, SmtpError> {
    let from = env
        .from
        .parse::<lettre::Address>()
        .map_err(|e| SmtpError::Rejected {
            reason: format!("invalid From address: {e}"),
        })?;
    let mut to = Vec::with_capacity(env.to.len());
    for addr in &env.to {
        let parsed = addr
            .parse::<lettre::Address>()
            .map_err(|e| SmtpError::Rejected {
                reason: format!("invalid recipient address: {e}"),
            })?;
        to.push(parsed);
    }
    lettre::address::Envelope::new(Some(from), to).map_err(|e| SmtpError::Rejected {
        reason: format!("envelope: {e}"),
    })
}

/// Format a lettre SMTP response as a human-readable string.
fn format_response(response: &lettre::transport::smtp::response::Response) -> String {
    format!(
        "{} {}",
        response.code(),
        response.message().collect::<Vec<_>>().join(" ")
    )
}

/// Classify a lettre SMTP error into our error taxonomy.
fn classify_smtp_error(err: lettre::transport::smtp::Error) -> SmtpError {
    if err.is_response() {
        SmtpError::Rejected {
            reason: err.to_string(),
        }
    } else if err.is_client() {
        SmtpError::Connection(err)
    } else {
        SmtpError::Transport(err)
    }
}

#[cfg(test)]
mod tests {
    use rimap_config::model::{SmtpConfig, SmtpEncryption};

    use super::SmtpClient;

    fn test_config() -> SmtpConfig {
        SmtpConfig {
            host: "localhost".into(),
            port: 1025,
            encryption: SmtpEncryption::None,
            username: "test@example.com".into(),
            command_timeout_seconds: 5,
        }
    }

    #[test]
    fn client_builds_with_no_encryption() {
        let client = SmtpClient::new(&test_config(), "password");
        assert!(client.is_ok());
    }
}
