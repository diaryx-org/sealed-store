//! sealed-store: a sealed object store for hosts that are not trusted with what they
//! hold.
//!
//! Four layers, each usable without the one above it:
//!
//! - **Key material** ([`Root`], [`Keys`], [`Dek`], [`Kek`], the gates). A
//!   root is 32 random bytes; a key for content and a key for names are
//!   derived from it. A gate is a way in, a password or a 32-byte secret,
//!   and holds the content key wrapped under a key derived from its own
//!   secret, so a second way in is one more small blob and nothing sealed
//!   again.
//! - **Objects** ([`seal_object`], [`seal_derived`], [`open_object`]). One
//!   frame per object: gzipped, padded to a Padmé bucket, sealed with
//!   AES-256-GCM, and bound to the blinded name it is stored under.
//! - **Chunked objects** ([`seal_stream`], [`StreamOpener`]). A large object
//!   as many AEAD messages: sealed and opened in constant memory, and any
//!   range of it opened from the chunks that hold it.
//! - **A vault** ([`Vault`] over a [`Store`], with the `vault` feature, on by
//!   default). Files by path in a directory, a bucket or memory, whose keeper
//!   learns neither a file's name nor its bytes.
//!
//! ```
//! # #[cfg(feature = "vault")] {
//! use sealed_store::{MemStore, PasswordKdf, Vault};
//!
//! let store = MemStore::new();
//! // `Vault::create(&store, password)` in real use: these costs are a test's.
//! let vault = Vault::create_with(&store, "correct horse", PasswordKdf::mint_with(1024, 1, 1))?;
//! vault.put("journal/today.md", b"# Today")?;
//!
//! let again = Vault::open(&store, "correct horse")?;
//! assert_eq!(again.get("journal/today.md")?.as_deref(), Some(&b"# Today"[..]));
//! assert!(Vault::open(&store, "wrong horse").is_err());
//! # }
//! # Ok::<(), sealed_store::Error>(())
//! ```
//!
//! The format is written down in `docs/format.md`, with what it does not
//! claim. It has not been reviewed by anyone outside the project.

mod error;
mod keys;
mod object;
#[cfg(feature = "vault")]
mod store;
mod stream;
#[cfg(feature = "vault")]
mod vault;

pub use error::{Error, Result};
pub use keys::{
    Dek, GateKeys, GateSecret, Kek, Keys, PASSWORD_KDF_DEFAULTS, PasswordKdf, Proof, Root,
    StoreNames, derive_link_gate, derive_password_gate, hex, hkdf32, open_frame, reserved_name,
    seal_frame, sha256_hex, unwrap_dek, wrap_dek,
};
pub use object::{FRAME_OVERHEAD, open_object, padme, padme64, seal_derived, seal_object};
#[cfg(feature = "vault")]
pub use store::{DirStore, MemStore, Store, check_name};
pub use stream::{
    CHUNK_LOG2, ReadAt, STREAM_HEADER, StreamOpener, is_stream, open_stream, random_stream_salt,
    seal_stream, seal_stream_with, sealed_stream_len,
};
#[cfg(feature = "vault")]
pub use vault::{Entry, Gate, GateType, HEADER, Held, INLINE_LIMIT, Vault};
