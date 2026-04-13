//! `SmtpClient` — one-shot SMTP send via `lettre`.

use std::time::Duration;

use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Tokio1Executor};
use rimap_config::model::{SmtpConfig, SmtpEncryption};

use crate::error::SmtpError;

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
                .map_err(|e| SmtpError::Connection(e.to_string()))?
                .port(config.port),
            SmtpEncryption::Starttls => {
                AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.host)
                    .map_err(|e| SmtpError::Connection(e.to_string()))?
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
    pub async fn send_raw(
        &self,
        envelope: &lettre::address::Envelope,
        raw: &[u8],
    ) -> Result<String, SmtpError> {
        let response = self
            .transport
            .send_raw(envelope, raw)
            .await
            .map_err(classify_smtp_error)?;
        Ok(format_response(&response))
    }
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
        SmtpError::Connection(err.to_string())
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
