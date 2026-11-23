//! Error type.

/// Everything that can go wrong in this crate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Malformed input supplied by the caller (Secret Key, email, …).
    #[error("invalid input: {0}")]
    InvalidInput(String),
    /// Something the server or a stored object uses that this crate doesn't implement.
    #[error("unsupported: {0}")]
    Unsupported(String),
    /// The server misbehaved or a protocol check failed (bad SRP proof, bad MAC, …).
    #[error("protocol error: {0}")]
    Protocol(String),
    /// Decryption failed: wrong key, wrong password/Secret Key, or tampered data.
    #[error("decryption failed: {0}")]
    Decrypt(String),
    /// Malformed JSON or base64 in a server response or stored object.
    #[error("malformed data: {0}")]
    Malformed(String),
    /// The server rejected the request (HTTP status and body).
    #[error("server returned {status}: {body}")]
    Server {
        /// HTTP status code.
        status: u16,
        /// Response body (never contains secrets the client sent).
        body: String,
    },
    /// Network / HTTP error.
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Malformed(e.to_string())
    }
}

impl From<base64::DecodeError> for Error {
    fn from(e: base64::DecodeError) -> Self {
        Error::Malformed(format!("base64: {e}"))
    }
}

/// `Result` with this crate's [`Error`].
pub type Result<T> = std::result::Result<T, Error>;
