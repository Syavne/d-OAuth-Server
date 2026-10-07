//! Client repository types: the safe [`Client`] projection, the allowlisted
//! [`ClientMetadata`] update set, [`NewClient`] insert input, and the
//! [`TokenEndpointAuthMethod`] allowlist.

use std::fmt;

use time::OffsetDateTime;
use uuid::Uuid;

use crate::crypto::secret::SecretHashError;

/// Errors from the client repository.
///
/// No variant carries a secret or a stored hash.
#[derive(Debug, thiserror::Error)]
pub enum ClientRepoError {
  /// A database operation failed.
  #[error("database error: {0}")]
  Database(#[from] sqlx::Error),
  /// A stored client-secret hash could not be verified.
  #[error("client secret verification failed: {0}")]
  Secret(#[from] SecretHashError),
  /// The blocking secret-verification task panicked or was cancelled.
  #[error("secret verification task failed")]
  Task(#[from] tokio::task::JoinError),
  /// A row carried a `token_endpoint_auth_method` outside the allowlist.
  #[error("unknown token_endpoint_auth_method: {0}")]
  UnknownAuthMethod(String),
}

/// A registered client's metadata.
///
/// This is the safe projection: it never contains `client_secret_hash` or
/// `registration_access_token_hash`.
///
/// `Debug` redacts every sealed PII field (RFC 7591 §3.2.2 metadata): the
/// rendered form carries `[REDACTED]` for `client_name`, `jwks_uri`,
/// `tls_client_auth_subject_dn`, `tls_client_auth_cert_thumbprint`,
/// `request_uris`, `contacts`, and `software_id`, so PII never reaches a log.
#[derive(Clone, PartialEq)]
pub struct Client {
  /// Surrogate primary key.
  pub id: Uuid,
  /// Stable public client identifier.
  pub client_id: String,
  /// When the client secret expires, if it does.
  pub client_secret_expires_at: Option<OffsetDateTime>,
  /// When the client identifier was issued.
  pub client_id_issued_at: OffsetDateTime,
  /// Human-readable client name.
  pub client_name: String,
  /// Registered grant types.
  pub grant_types: Vec<String>,
  /// Registered response types.
  pub response_types: Vec<String>,
  /// Space-delimited default scope string.
  pub scope: String,
  /// Registered token-endpoint authentication method.
  pub token_endpoint_auth_method: String,
  /// Inline JWKS document, if any.
  pub jwks: Option<serde_json::Value>,
  /// Remote JWKS URI, if any.
  pub jwks_uri: Option<String>,
  /// mTLS subject DN, if enrolled.
  pub tls_client_auth_subject_dn: Option<String>,
  /// mTLS certificate SHA-256 thumbprint, if enrolled.
  pub tls_client_auth_cert_thumbprint: Option<String>,
  /// Pre-registered JAR `request_uri` values (RFC 9101), if any.
  pub request_uris: Option<serde_json::Value>,
  /// Contact addresses.
  pub contacts: Option<serde_json::Value>,
  /// Software identifier.
  pub software_id: Option<String>,
  /// Whether the client registered DPoP-bound access tokens (RFC 9449 §5).
  pub dpop_bound_access_tokens: bool,
  /// Whether the client is active (soft-delete flag).
  pub active: bool,
  /// Row creation timestamp.
  pub created_at: OffsetDateTime,
  /// Row last-update timestamp.
  pub updated_at: OffsetDateTime,
}

impl fmt::Debug for Client {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("Client")
      .field("id", &self.id)
      .field("client_id", &self.client_id)
      .field("client_secret_expires_at", &self.client_secret_expires_at)
      .field("client_id_issued_at", &self.client_id_issued_at)
      .field("client_name", &"[REDACTED]")
      .field("grant_types", &self.grant_types)
      .field("response_types", &self.response_types)
      .field("scope", &self.scope)
      .field(
        "token_endpoint_auth_method",
        &self.token_endpoint_auth_method,
      )
      .field("jwks", &self.jwks)
      .field("jwks_uri", &"[REDACTED]")
      .field("tls_client_auth_subject_dn", &"[REDACTED]")
      .field("tls_client_auth_cert_thumbprint", &"[REDACTED]")
      .field("request_uris", &"[REDACTED]")
      .field("contacts", &"[REDACTED]")
      .field("software_id", &"[REDACTED]")
      .field("dpop_bound_access_tokens", &self.dpop_bound_access_tokens)
      .field("active", &self.active)
      .field("created_at", &self.created_at)
      .field("updated_at", &self.updated_at)
      .finish()
  }
}

impl Client {
  /// Parse this client's registered `token_endpoint_auth_method`.
  ///
  /// # Errors
  ///
  /// Returns [`ClientRepoError::UnknownAuthMethod`] for a row outside the
  /// RFC 7591 allowlist.
  pub fn auth_method(&self) -> Result<TokenEndpointAuthMethod, ClientRepoError> {
    TokenEndpointAuthMethod::try_from(self.token_endpoint_auth_method.as_str())
  }
}

/// The allowlisted, full-replace metadata of a client.
///
/// This is exactly the column set [`super::update_metadata`] may write;
/// identity, secret, issue time, active flag, and registration token are
/// deliberately absent so a metadata update can never touch them.
///
/// `Debug` redacts the sealed PII subset with the same `[REDACTED]` rule as
/// [`Client`].
#[derive(Clone, PartialEq)]
pub struct ClientMetadata {
  /// Human-readable client name.
  pub client_name: String,
  /// Registered grant types.
  pub grant_types: Vec<String>,
  /// Registered response types.
  pub response_types: Vec<String>,
  /// Space-delimited default scope string.
  pub scope: String,
  /// Registered token-endpoint authentication method.
  pub token_endpoint_auth_method: String,
  /// Inline JWKS document, if any.
  pub jwks: Option<serde_json::Value>,
  /// Remote JWKS URI, if any.
  pub jwks_uri: Option<String>,
  /// mTLS subject DN, if enrolled.
  pub tls_client_auth_subject_dn: Option<String>,
  /// mTLS certificate SHA-256 thumbprint, if enrolled.
  pub tls_client_auth_cert_thumbprint: Option<String>,
  /// Pre-registered JAR `request_uri` values, if any.
  pub request_uris: Option<serde_json::Value>,
  /// Contact addresses.
  pub contacts: Option<serde_json::Value>,
  /// Software identifier.
  pub software_id: Option<String>,
  /// Whether the client registers DPoP-bound access tokens (RFC 9449 §5).
  pub dpop_bound_access_tokens: bool,
}

impl fmt::Debug for ClientMetadata {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.debug_struct("ClientMetadata")
      .field("client_name", &"[REDACTED]")
      .field("grant_types", &self.grant_types)
      .field("response_types", &self.response_types)
      .field("scope", &self.scope)
      .field(
        "token_endpoint_auth_method",
        &self.token_endpoint_auth_method,
      )
      .field("jwks", &self.jwks)
      .field("jwks_uri", &"[REDACTED]")
      .field("tls_client_auth_subject_dn", &"[REDACTED]")
      .field("tls_client_auth_cert_thumbprint", &"[REDACTED]")
      .field("request_uris", &"[REDACTED]")
      .field("contacts", &"[REDACTED]")
      .field("software_id", &"[REDACTED]")
      .field("dpop_bound_access_tokens", &self.dpop_bound_access_tokens)
      .finish()
  }
}

/// Input for [`super::insert`].
///
/// Deliberately does not derive `Debug`, since it carries a secret hash and a
/// registration-token hash.
pub struct NewClient {
  /// Surrogate primary key.
  pub id: Uuid,
  /// Stable public client identifier.
  pub client_id: String,
  /// Argon2id PHC hash of the client secret, or `None` for a public client.
  pub client_secret_hash: Option<String>,
  /// When the client secret expires, if it does.
  pub client_secret_expires_at: Option<OffsetDateTime>,
  /// Human-readable client name.
  pub client_name: String,
  /// Registered grant types.
  pub grant_types: Vec<String>,
  /// Registered response types.
  pub response_types: Vec<String>,
  /// Space-delimited default scope string.
  pub scope: String,
  /// Registered token-endpoint authentication method.
  pub token_endpoint_auth_method: String,
  /// Inline JWKS document, if any.
  pub jwks: Option<serde_json::Value>,
  /// Remote JWKS URI, if any.
  pub jwks_uri: Option<String>,
  /// mTLS subject DN, if enrolled.
  pub tls_client_auth_subject_dn: Option<String>,
  /// mTLS certificate SHA-256 thumbprint, if enrolled.
  pub tls_client_auth_cert_thumbprint: Option<String>,
  /// Pre-registered JAR `request_uri` values, if any.
  pub request_uris: Option<serde_json::Value>,
  /// Contact addresses.
  pub contacts: Option<serde_json::Value>,
  /// Software identifier.
  pub software_id: Option<String>,
  /// Whether the client registers DPoP-bound access tokens (RFC 9449 §5).
  pub dpop_bound_access_tokens: bool,
  /// Keyed hash of the RFC 7592 registration access token, if issued.
  pub registration_access_token_hash: Option<String>,
}

/// A token-endpoint authentication method understood by the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenEndpointAuthMethod {
  /// HTTP Basic with `client_id`/`client_secret`.
  ClientSecretBasic,
  /// Form-body `client_id`/`client_secret`.
  ClientSecretPost,
  /// Public client (no secret).
  None,
  /// RFC 7523 JWT client assertion.
  PrivateKeyJwt,
  /// RFC 8705 mutual-TLS with a CA-issued certificate.
  TlsClientAuth,
  /// RFC 8705 self-signed mutual-TLS certificate.
  SelfSignedTlsClientAuth,
}

impl TokenEndpointAuthMethod {
  /// The wire value stored in `token_endpoint_auth_method`.
  #[must_use]
  pub const fn as_str(self) -> &'static str {
    match self {
      Self::ClientSecretBasic => "client_secret_basic",
      Self::ClientSecretPost => "client_secret_post",
      Self::None => "none",
      Self::PrivateKeyJwt => "private_key_jwt",
      Self::TlsClientAuth => "tls_client_auth",
      Self::SelfSignedTlsClientAuth => "self_signed_tls_client_auth",
    }
  }
}

impl TryFrom<&str> for TokenEndpointAuthMethod {
  type Error = ClientRepoError;

  fn try_from(value: &str) -> Result<Self, Self::Error> {
    match value {
      "client_secret_basic" => Ok(Self::ClientSecretBasic),
      "client_secret_post" => Ok(Self::ClientSecretPost),
      "none" => Ok(Self::None),
      "private_key_jwt" => Ok(Self::PrivateKeyJwt),
      "tls_client_auth" => Ok(Self::TlsClientAuth),
      "self_signed_tls_client_auth" => Ok(Self::SelfSignedTlsClientAuth),
      other => Err(ClientRepoError::UnknownAuthMethod(other.to_owned())),
    }
  }
}
