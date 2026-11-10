//! What can go wrong, and how little of it a caller is told.

use std::fmt;

/// An error from this crate.
///
/// Opening says one thing for a wrong key, a wrong binding and a tampered
/// byte, because the cipher cannot tell them apart and a caller that could
/// would have an oracle.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// An encoded secret, salt or blob that does not decode to what it should.
    Encoding(String),
    /// Argon2id refused its parameters or its input, in its words.
    Kdf(String),
    /// The cipher refused to seal. Not reachable with a body the frame holds.
    Seal,
    /// Wrong key, wrong name or context, or a tampered frame.
    Open,
    /// Bytes that are not a frame of the kind asked for.
    Frame(&'static str),
    /// A compressed body past the frame's 32-bit length.
    TooLarge,
    /// gzip or gunzip failed.
    Compression(String),
    /// The store under a vault failed, or holds something a vault did not put
    /// there.
    Store(String),
    /// A vault that cannot be made or opened as asked.
    Vault(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Encoding(what) => write!(f, "{what}"),
            Error::Kdf(what) => write!(f, "{what}"),
            Error::Seal => write!(f, "seal failed"),
            Error::Open => write!(f, "open failed: wrong key, wrong name, or a tampered frame"),
            Error::Frame(what) => write!(f, "{what}"),
            Error::TooLarge => write!(f, "object exceeds u32 compressed length"),
            Error::Compression(what) => write!(f, "gzip: {what}"),
            Error::Store(what) => write!(f, "store: {what}"),
            Error::Vault(what) => write!(f, "{what}"),
        }
    }
}

impl std::error::Error for Error {}

/// So `?` carries an error out of a function that reports in words, as
/// diaryx's publisher does throughout.
impl From<Error> for String {
    fn from(e: Error) -> String {
        e.to_string()
    }
}

pub type Result<T> = std::result::Result<T, Error>;
