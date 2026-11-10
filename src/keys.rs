//! Key material: a gate's two halves, a root and the working keys derived
//! from it, and the wrap that carries a content key through a gate.
//!
//! Every derivation here runs on the device that holds the secret. A host
//! sees a proof's hash, a wrap and sealed frames, and can derive nothing from
//! any of them.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};

// The format's labels. `diaryx-ep-v1` is where the format was first written
// down (diaryx's Encrypted Publishing Spec, Appendix A); a breaking change to
// any of them is a new prefix, not an edit.
pub(crate) const INFO_GATE_PROOF: &[u8] = b"diaryx-ep-v1/gate-proof";
pub(crate) const INFO_GATE_KEK: &[u8] = b"diaryx-ep-v1/gate-kek";
const INFO_DEK: &[u8] = b"diaryx-ep-v1/dek";
const INFO_BLIND: &[u8] = b"diaryx-ep-v1/blind";
const INFO_MANIFEST: &[u8] = b"diaryx-ep-v1/manifest";
const INFO_NONCE: &[u8] = b"diaryx-ep-v1/nonce";
const INFO_STREAM_SALT: &[u8] = b"diaryx-ep-v1/stream-salt";
const INFO_STORE_BLIND: &[u8] = b"diaryx-ep-v1/store-blind";
const AAD_WRAP: &[u8] = b"diaryx-ep-v1/wrap";

/// Default Argon2id costs for a new password gate, in the order a gate record
/// stores them: (m KiB, t, p). A gate already made carries its own.
pub const PASSWORD_KDF_DEFAULTS: (u32, u32, u32) = (65536, 3, 1);

fn hkdf_expand(ikm: &[u8], info: &[u8], out: &mut [u8]) {
    // Empty salt throughout: every IKM is already uniform, and the labels
    // carry the separation.
    Hkdf::<Sha256>::new(None, ikm)
        .expand(info, out)
        .expect("output length is always <= 255 * 32");
}

/// HKDF-SHA-256 with an empty salt, 32 bytes out: the one expansion every
/// label in the format goes through. For a caller deriving a key of its own
/// under a label of its own.
pub fn hkdf32(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    hkdf_expand(ikm, info, &mut out);
    out
}

/// Lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Lowercase-hex SHA-256.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn random32() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// `nonce(12, random) ‖ AES-256-GCM(key, nonce, msg, aad)`: the frame every
/// random-nonce seal in the format shares. What tells one use from another is
/// the AAD each caller binds.
pub fn seal_frame(key: &[u8; 32], aad: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("32-byte key");
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(&Nonce::from(nonce), Payload { msg, aad })
        .map_err(|_| Error::Seal)?;
    let mut blob = Vec::with_capacity(12 + ct.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ct);
    Ok(blob)
}

/// The inverse of [`seal_frame`]. An error for a wrong key, a wrong AAD, a
/// tampered byte or a frame too short to hold a nonce, and it does not say
/// which, because GCM cannot.
pub fn open_frame(key: &[u8; 32], aad: &[u8], blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < 12 {
        return Err(Error::Frame("frame too short"));
    }
    let (nonce, ct) = blob.split_at(12);
    let nonce: [u8; 12] = nonce.try_into().expect("split_at(12)");
    let cipher = Aes256Gcm::new_from_slice(key).expect("32-byte key");
    cipher
        .decrypt(&Nonce::from(nonce), Payload { msg: ct, aad })
        .map_err(|_| Error::Open)
}

fn decode32(token: &str) -> Result<[u8; 32]> {
    let bytes = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|e| Error::Encoding(format!("not base64url: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| Error::Encoding("expected 32 bytes".to_string()))
}

/// A gate's root secret when the gate is not a password: 32 random bytes
/// minted on the owner's device. In a share link it is the fragment, the half
/// a browser never transmits; for a vault it is a recovery key.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct GateSecret(pub(crate) [u8; 32]);

impl GateSecret {
    pub fn mint() -> Self {
        Self(random32())
    }

    /// The secret as base64url, the form a person is handed.
    pub fn token(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }

    pub fn from_token(token: &str) -> Result<Self> {
        decode32(token).map(Self)
    }
}

/// The host-facing half of a gate: presented to be let in, and stored by the
/// host only as its hash.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Proof(pub(crate) [u8; 32]);

impl Proof {
    /// The presented credential, base64url. It never contains `.`.
    pub fn token(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }

    /// What a gate record stores: `hex(SHA-256(proof))`. The proof is
    /// high-entropy under both kinds of gate, so a fast hash is enough.
    pub fn hash_hex(&self) -> String {
        hex(&Sha256::digest(self.0))
    }
}

/// A key that wraps another key or seals a small message: the half of a gate
/// that never leaves the device, or a key derived from a [`Dek`] for one job.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Kek(pub(crate) [u8; 32]);

impl Kek {
    /// Storage form (base64url), for a KEK its owner has to keep: a password
    /// gate's exists only while the password is typed. Never for a host.
    pub fn token(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }

    pub fn from_token(token: &str) -> Result<Self> {
        decode32(token).map(Self)
    }

    /// Seal a message under this key in a [`seal_frame`], bound to `aad`.
    pub fn seal(&self, aad: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
        seal_frame(&self.0, aad, msg)
    }

    /// Open what [`Kek::seal`] made under the same `aad`.
    pub fn open(&self, aad: &[u8], blob: &[u8]) -> Result<Vec<u8>> {
        open_frame(&self.0, aad, blob)
    }
}

/// Both halves of one gate. They are derived apart, so a host holding every
/// proof it was ever shown learns nothing about any KEK.
pub struct GateKeys {
    pub proof: Proof,
    pub kek: Kek,
}

/// The gate a [`GateSecret`] opens: two HKDF expansions of it.
pub fn derive_link_gate(secret: &GateSecret) -> GateKeys {
    GateKeys {
        proof: Proof(hkdf32(&secret.0, INFO_GATE_PROOF)),
        kek: Kek(hkdf32(&secret.0, INFO_GATE_KEK)),
    }
}

/// Argon2id parameters for a password gate. Stored beside the gate in the
/// clear: a reader has to derive before it can open anything.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasswordKdf {
    pub m_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub salt: [u8; 16],
}

impl PasswordKdf {
    /// [`PASSWORD_KDF_DEFAULTS`] and a fresh salt.
    pub fn mint() -> Self {
        let (m_kib, t_cost, p_cost) = PASSWORD_KDF_DEFAULTS;
        Self::mint_with(m_kib, t_cost, p_cost)
    }

    /// Costs of the caller's choosing and a fresh salt.
    pub fn mint_with(m_kib: u32, t_cost: u32, p_cost: u32) -> Self {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        Self {
            m_kib,
            t_cost,
            p_cost,
            salt,
        }
    }

    pub fn salt_b64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.salt)
    }

    pub fn from_stored(m_kib: u32, t_cost: u32, p_cost: u32, salt_b64: &str) -> Result<Self> {
        let bytes = URL_SAFE_NO_PAD
            .decode(salt_b64)
            .map_err(|e| Error::Encoding(format!("salt not base64url: {e}")))?;
        let salt: [u8; 16] = bytes
            .try_into()
            .map_err(|_| Error::Encoding("salt must be 16 bytes".to_string()))?;
        Ok(Self {
            m_kib,
            t_cost,
            p_cost,
            salt,
        })
    }
}

/// The gate a password opens: one Argon2id run, 64 bytes out, split down the
/// middle, proof first and KEK second. The slow function is paid once for
/// both halves.
pub fn derive_password_gate(password: &str, kdf: &PasswordKdf) -> Result<GateKeys> {
    let params = Params::new(kdf.m_kib, kdf.t_cost, kdf.p_cost, Some(64))
        .map_err(|e| Error::Kdf(format!("argon2 params: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 64];
    argon
        .hash_password_into(password.as_bytes(), &kdf.salt, &mut out)
        .map_err(|e| Error::Kdf(format!("argon2: {e}")))?;
    let mut proof = [0u8; 32];
    let mut kek = [0u8; 32];
    proof.copy_from_slice(&out[..32]);
    kek.copy_from_slice(&out[32..]);
    out.zeroize();
    Ok(GateKeys {
        proof: Proof(proof),
        kek: Kek(kek),
    })
}

/// The root secret everything else derives from: 32 random bytes that never
/// leave the device that minted them, except wrapped.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Root(pub(crate) [u8; 32]);

/// The data encryption key: what content is sealed under, and the only key a
/// reader who is not the owner ever holds.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Dek(pub(crate) [u8; 32]);

impl Dek {
    /// A DEK from bytes the caller derived itself, to seal objects under a
    /// key that has no [`Root`] above it.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Dek(bytes)
    }

    /// A key for one job, derived from this one and labelled apart from every
    /// other use of it: `HKDF(dek, info)`. Whoever holds the DEK holds it.
    pub fn derive_kek(&self, info: &[u8]) -> Kek {
        Kek(hkdf32(&self.0, info))
    }

    /// A name for this key that discloses nothing about it, to say whether
    /// two are the same: the first 16 bytes of
    /// `SHA-256("diaryx-ep-v1/dek-id" ‖ 0x00 ‖ dek)`, hex.
    pub fn fingerprint(&self) -> String {
        fingerprint(b"diaryx-ep-v1/dek-id", &self.0)
    }
}

fn fingerprint(label: &[u8], key: &[u8; 32]) -> String {
    let mut h = Sha256::new();
    h.update(label);
    h.update([0u8]);
    h.update(key);
    hex(&h.finalize()[..16])
}

/// A root's working keys, one per job: content, names, and a manifest.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Keys {
    pub(crate) dek: [u8; 32],
    pub(crate) blind: [u8; 32],
    pub(crate) manifest: [u8; 32],
}

impl Root {
    pub fn mint() -> Self {
        Self(random32())
    }

    /// Storage form (base64url), for a secret store on the owner's device.
    pub fn encode(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }

    pub fn decode(stored: &str) -> Result<Self> {
        decode32(stored).map(Self)
    }

    /// A name for this root that discloses nothing about it: the first 16
    /// bytes of `SHA-256("diaryx-ep-v1/root-id" ‖ 0x00 ‖ root)`, hex. For
    /// saying which root something was sealed under without carrying the
    /// root. Local only.
    pub fn fingerprint(&self) -> String {
        fingerprint(b"diaryx-ep-v1/root-id", &self.0)
    }

    pub fn keys(&self) -> Keys {
        Keys {
            dek: hkdf32(&self.0, INFO_DEK),
            blind: hkdf32(&self.0, INFO_BLIND),
            manifest: hkdf32(&self.0, INFO_MANIFEST),
        }
    }

    /// The salt a chunked object is sealed under when its ciphertext has to be
    /// reproducible ([`crate::seal_stream`]): the first 16 bytes of
    /// `HKDF(root, "diaryx-ep-v1/stream-salt" ‖ 0x00 ‖ name ‖ 0x00 ‖ content_hash)`,
    /// `content_hash_hex` being the lowercase-hex SHA-256 of the plaintext. A
    /// chunked object is not compressed, so the plaintext is what is sealed,
    /// and the salt repeats only when the name and every byte do.
    pub fn stream_salt(&self, name_input: &str, content_hash_hex: &str) -> [u8; 16] {
        let mut info = Vec::with_capacity(
            INFO_STREAM_SALT.len() + name_input.len() + content_hash_hex.len() + 2,
        );
        info.extend_from_slice(INFO_STREAM_SALT);
        info.push(0);
        info.extend_from_slice(name_input.as_bytes());
        info.push(0);
        info.extend_from_slice(content_hash_hex.as_bytes());
        let mut out = [0u8; 16];
        hkdf_expand(&self.0, &info, &mut out);
        out
    }

    /// The nonce an object is sealed under when its ciphertext has to be
    /// reproducible. It repeats only when the bytes GCM encrypts repeat, which
    /// reproduces the identical ciphertext and nothing else. `body_hash_hex`
    /// is the lowercase-hex SHA-256 of those bytes: the compressed, padded
    /// body, never the plaintext it came from, because two compressors turn
    /// one plaintext into two bodies and a nonce taken from the plaintext
    /// would seal both under one key and one nonce.
    pub(crate) fn object_nonce(&self, name_input: &str, body_hash_hex: &str) -> [u8; 12] {
        let mut info =
            Vec::with_capacity(INFO_NONCE.len() + name_input.len() + body_hash_hex.len() + 2);
        info.extend_from_slice(INFO_NONCE);
        info.push(0);
        info.extend_from_slice(name_input.as_bytes());
        info.push(0);
        info.extend_from_slice(body_hash_hex.as_bytes());
        let mut out = [0u8; 12];
        hkdf_expand(&self.0, &info, &mut out);
        out
    }
}

fn blinded(key: &[u8; 32], name_input: &str) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("any key length works");
    mac.update(name_input.as_bytes());
    hex(&mac.finalize().into_bytes()[..16])
}

impl Keys {
    pub fn dek(&self) -> Dek {
        Dek(self.dek)
    }

    /// The blinded name of an object: `hex(HMAC-SHA-256(blind, name)[0..16])`.
    /// Deterministic, so an unchanged object keeps its name; per root, so two
    /// roots never produce a matching name; 128 bits, because a flat namespace
    /// makes names a collision surface.
    pub fn object_key(&self, name_input: &str) -> String {
        blinded(&self.blind, name_input)
    }

    pub fn manifest_key(&self) -> [u8; 32] {
        self.manifest
    }
}

/// Wrap a DEK under one gate's KEK: a [`seal_frame`] whose AAD binds
/// `context`, the name of what the DEK is for, so a wrap cannot be replayed
/// onto another.
pub fn wrap_dek(kek: &Kek, dek: &Dek, context: &str) -> Result<Vec<u8>> {
    seal_frame(&kek.0, &wrap_aad(context), &dek.0)
}

/// Unwrap what [`wrap_dek`] made, under the same `context`.
pub fn unwrap_dek(kek: &Kek, blob: &[u8], context: &str) -> Result<Dek> {
    let pt = open_frame(&kek.0, &wrap_aad(context), blob)?;
    let arr: [u8; 32] = pt
        .try_into()
        .map_err(|_| Error::Frame("unwrapped DEK is not 32 bytes"))?;
    Ok(Dek(arr))
}

fn wrap_aad(context: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_WRAP.len() + context.len());
    aad.extend_from_slice(AAD_WRAP);
    aad.extend_from_slice(context.as_bytes());
    aad
}

/// A reserved name: one for an object the caller's own naming scheme has no
/// name for. NUL-prefixed, so it cannot collide with a name that holds no
/// NUL.
pub fn reserved_name(label: &str) -> String {
    format!("\u{0}{label}")
}

/// Names a holder of the DEK alone can derive.
///
/// [`Keys::object_key`] names an object under the blind key, which a reader
/// never holds: a reader reaches such an object only by a reference the owner
/// wrote into another. Where a reader has to name an object before reading
/// anything, its name comes from here: a key expanded from the DEK, so the
/// content key is never also a naming key, and the same 128-bit truncation.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct StoreNames([u8; 32]);

impl StoreNames {
    pub fn from_dek(dek: &Dek) -> Self {
        Self(hkdf32(&dek.0, INFO_STORE_BLIND))
    }

    /// The blinded name of the object with this label.
    pub fn object_key(&self, label: &str) -> String {
        blinded(&self.0, label)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Vectors generated independently with Python hashlib/hmac (HKDF per
    // RFC 5869, empty salt), not with this module. If these fail, this side
    // drifted from the format, not the other way around.
    const VEC_SECRET: [u8; 32] = [1; 32];
    const VEC_ROOT: [u8; 32] = [2; 32];
    const VEC_NAME: &str = "b4rk9d";

    #[test]
    fn link_gate_matches_independent_vectors() {
        let keys = derive_link_gate(&GateSecret(VEC_SECRET));
        assert_eq!(
            hex(&keys.proof.0),
            "cdb2c1687319a7bc340facd394fe182e3e2100d6365438bdc622d1077abf7672"
        );
        assert_eq!(
            hex(&keys.kek.0),
            "4c51647db0243f59a0ebca610710ac7be79c8819713656cedbee76e45d90cecc"
        );
        assert_eq!(
            keys.proof.hash_hex(),
            "013bd41b3b25cb2f340ac8bd282984f809f6cc3521f1a6bc348e42c0a176600e"
        );
        assert_eq!(
            keys.proof.token(),
            "zbLBaHMZp7w0D6zTlP4YLj4hANY2VDi9xiLRB3q_dnI"
        );
    }

    #[test]
    fn root_keys_match_independent_vectors() {
        let root = Root(VEC_ROOT);
        let keys = root.keys();
        assert_eq!(
            hex(&keys.dek),
            "8f66fcd4985ea4b1a83bdc24a9ab5a27ae8fa90a770d8f453ad3574aef921621"
        );
        assert_eq!(
            hex(&keys.blind),
            "4ec79ac48e327eb240fae13f1e4906f94657151cf123ecab46a8dd7d8ecbaba4"
        );
        assert_eq!(
            hex(&keys.manifest),
            "ea58feeac3a98386a0e31b183c3f4ddc176f3ff5625ace26e6ca05c5118d950e"
        );
        assert_eq!(
            keys.object_key(VEC_NAME),
            "2483a2238d98257737af039fd0436f09"
        );
    }

    #[test]
    fn object_nonce_matches_independent_vector() {
        let root = Root(VEC_ROOT);
        let body_hash = sha256_hex(b"hello");
        assert_eq!(
            hex(&root.object_nonce(VEC_NAME, &body_hash)),
            "285b45e568acdad674f586a3"
        );
    }

    #[test]
    fn derived_keks_match_independent_vectors() {
        // HKDF-SHA-256, empty salt, IKM 32 zero bytes, cross-checked by hand
        // from RFC 5869 with Python's `hmac`: the infos are diaryx's gift and
        // roster labels, which reach HKDF through `derive_kek` unchanged.
        let dek = Dek([0u8; 32]);
        assert_eq!(
            hex(&dek
                .derive_kek(b"diaryx-ep-v1/gift-kek\0dxbcdfgh6\0reunion")
                .0),
            "d62e0d00183039934ab34d36d9e9c8da86f7debfb80c72aff687227862ec259a"
        );
        assert_eq!(
            hex(&dek.derive_kek(b"diaryx-ep-v1/roster-kek\x007kq2m9xwg4ab").0),
            "8f2b256b103399ab3578463dce922b6e9eadffce1bf0ad79d4ae06b0f1b8cd08"
        );
    }

    #[test]
    fn proof_token_never_contains_a_dot() {
        for _ in 0..8 {
            let keys = derive_link_gate(&GateSecret::mint());
            assert!(!keys.proof.token().contains('.'));
        }
    }

    #[test]
    fn secret_round_trips_through_its_token() {
        let secret = GateSecret::mint();
        let back = GateSecret::from_token(&secret.token()).unwrap();
        assert_eq!(secret.0, back.0);
        assert!(GateSecret::from_token("too-short").is_err());
    }

    fn cheap_kdf() -> PasswordKdf {
        PasswordKdf {
            m_kib: 1024,
            t_cost: 1,
            p_cost: 1,
            salt: [3; 16],
        }
    }

    #[test]
    fn password_gate_is_deterministic_and_split_halves_differ() {
        let kdf = cheap_kdf();
        let a = derive_password_gate("correct horse", &kdf).unwrap();
        let b = derive_password_gate("correct horse", &kdf).unwrap();
        assert_eq!(a.proof.0, b.proof.0);
        assert_eq!(a.kek.0, b.kek.0);
        assert_ne!(a.proof.0, a.kek.0);
        let other = derive_password_gate("wrong horse", &kdf).unwrap();
        assert_ne!(a.proof.0, other.proof.0);
    }

    #[test]
    fn password_gate_matches_the_browser_vector() {
        // diaryx's reader shell derives this same gate in a browser, and its
        // `workers/site-proxy/test/argon2.test.ts` pins these exact bytes.
        // Cross-checked there against `hash-wasm`, a C implementation with no
        // RustCrypto in it, so this is a vector for Argon2id and not for the
        // crate both sides happen to share.
        let kdf = cheap_kdf();
        let keys = derive_password_gate("correct horse", &kdf).unwrap();
        assert_eq!(
            hex(&keys.proof.0),
            "84536e2c3d5c1e2c3d2b2971f5fae648d4c00739a43c5dc566d26e4cfbad36e6"
        );
        assert_eq!(
            hex(&keys.kek.0),
            "e03c69f3a8795743bca202982146a4422c8d18ccef7e9394f8ccaf17b92a455f"
        );
        assert_eq!(kdf.salt_b64(), "AwMDAwMDAwMDAwMDAwMDAw");
    }

    #[test]
    fn password_kdf_round_trips_through_stored_form() {
        let kdf = PasswordKdf::mint();
        let back =
            PasswordKdf::from_stored(kdf.m_kib, kdf.t_cost, kdf.p_cost, &kdf.salt_b64()).unwrap();
        assert_eq!(kdf, back);
        assert!(PasswordKdf::from_stored(1024, 1, 1, "AAAA").is_err());
    }

    #[test]
    fn wrap_round_trips_and_binds_its_context() {
        let root = Root::mint();
        let dek = root.keys().dek();
        let kek = derive_link_gate(&GateSecret::mint()).kek;
        let blob = wrap_dek(&kek, &dek, "family").unwrap();
        assert_eq!(unwrap_dek(&kek, &blob, "family").unwrap().0, dek.0);
        assert!(matches!(
            unwrap_dek(&kek, &blob, "partner"),
            Err(Error::Open)
        ));
        let other_kek = derive_link_gate(&GateSecret::mint()).kek;
        assert!(unwrap_dek(&other_kek, &blob, "family").is_err());
        assert!(unwrap_dek(&kek, &blob[..8], "family").is_err());
    }

    #[test]
    fn a_kek_seals_under_an_aad_and_opens_under_no_other() {
        let kek = derive_link_gate(&GateSecret::mint()).kek;
        let other = derive_link_gate(&GateSecret::mint()).kek;
        let blob = kek.seal(b"return:ns", b"payload").unwrap();
        assert_eq!(kek.open(b"return:ns", &blob).unwrap(), b"payload");
        assert!(other.open(b"return:ns", &blob).is_err());
        assert!(kek.open(b"return:other", &blob).is_err());
        let mut tampered = blob.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(kek.open(b"return:ns", &tampered).is_err());
    }

    #[test]
    fn reserved_names_cannot_collide_with_plain_ones() {
        let keys = Root::mint().keys();
        let reserved = keys.object_key(&reserved_name("index"));
        let real = keys.object_key("index");
        assert_ne!(reserved, real);
        assert!(reserved_name("index").starts_with('\u{0}'));
    }

    #[test]
    fn nonce_repeats_only_with_identical_body() {
        let root = Root::mint();
        let h1 = sha256_hex(b"one");
        let h2 = sha256_hex(b"two");
        assert_eq!(root.object_nonce("a1", &h1), root.object_nonce("a1", &h1));
        assert_ne!(root.object_nonce("a1", &h1), root.object_nonce("a1", &h2));
        assert_ne!(root.object_nonce("a1", &h1), root.object_nonce("a2", &h1));
    }

    #[test]
    fn fingerprints_tell_keys_apart_and_are_not_the_keys() {
        let a = Root::mint();
        let b = Root::mint();
        assert_eq!(a.fingerprint(), a.clone().fingerprint());
        assert_ne!(a.fingerprint(), b.fingerprint());
        assert_ne!(a.keys().dek().fingerprint(), a.fingerprint());
        assert_eq!(a.keys().dek().fingerprint().len(), 32);
    }
}
