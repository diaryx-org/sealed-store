//! The object frame: what a host stores under a blinded name.
//!
//! `"DEP1" ‖ nonce(12) ‖ AES-256-GCM(dek, nonce, body, aad)`, with
//! `aad = "diaryx-ep-v1/obj" ‖ object_key` and
//! `body = u32-le gzip_length ‖ gzip(plaintext) ‖ zero padding` out to the
//! body's Padmé bucket.
//!
//! The AAD binds a ciphertext to its blinded name, so a host that swaps two
//! frames between names produces a failure to open and not one object served
//! as another. That is the whole of the claim: nothing binds a frame to a
//! version, and a host that kept an earlier frame under a name can serve it
//! again.
//!
//! A frame is one AEAD message, held whole in memory to seal and to open. A
//! large object wants the chunked frame in [`crate::seal_stream`].

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

use crate::error::{Error, Result};
use crate::keys::{Dek, Root, sha256_hex};

const OBJ_MAGIC: &[u8; 4] = b"DEP1";
const AAD_OBJ: &[u8] = b"diaryx-ep-v1/obj";

/// What a frame adds to its body: the magic, the nonce and GCM's tag.
pub const FRAME_OVERHEAD: usize = 4 + 12 + 16;

/// Padmé bucket for `len`: a size whose relative overhead shrinks as objects
/// grow (at most about 12%), leaking only O(log log n) bits of the true
/// length. <https://petsymposium.org/2019/files/papers/issue4/popets-2019-0056.pdf>
pub fn padme(len: usize) -> usize {
    padme64(len as u64) as usize
}

/// [`padme`] over a length that need not fit in memory.
pub fn padme64(len: u64) -> u64 {
    if len < 2 {
        return len;
    }
    let e = u64::BITS - 1 - len.leading_zeros();
    let s = u32::BITS - e.leading_zeros();
    let mask = (1u64 << (e - s)) - 1;
    (len + mask) & !mask
}

fn obj_aad(object_key: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_OBJ.len() + object_key.len());
    aad.extend_from_slice(AAD_OBJ);
    aad.extend_from_slice(object_key.as_bytes());
    aad
}

fn compress(plaintext: &[u8]) -> Result<Vec<u8>> {
    use std::io::Write;
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(plaintext)
        .map_err(|e| Error::Compression(e.to_string()))?;
    enc.finish().map_err(|e| Error::Compression(e.to_string()))
}

/// What GCM encrypts: the compressed object, length-prefixed and padded to
/// its Padmé bucket. The prefix is what makes the padding unambiguous to
/// strip.
fn object_body(gz: &[u8]) -> Result<Vec<u8>> {
    let gz_len = u32::try_from(gz.len()).map_err(|_| Error::TooLarge)?;
    let unpadded = 4 + gz.len();
    let mut body = Vec::with_capacity(padme(unpadded));
    body.extend_from_slice(&gz_len.to_le_bytes());
    body.extend_from_slice(gz);
    body.resize(padme(unpadded), 0);
    Ok(body)
}

fn seal_body(dek: &Dek, nonce: &[u8; 12], object_key: &str, body: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(&dek.0).expect("32-byte key");
    let ct = cipher
        .encrypt(
            &Nonce::from(*nonce),
            Payload {
                msg: body,
                aad: &obj_aad(object_key),
            },
        )
        .map_err(|_| Error::Seal)?;

    let mut frame = Vec::with_capacity(4 + 12 + ct.len());
    frame.extend_from_slice(OBJ_MAGIC);
    frame.extend_from_slice(nonce);
    frame.extend_from_slice(&ct);
    Ok(frame)
}

/// Seal one object under a nonce the caller drew at random. A caller that
/// wants the same bytes back from the same plaintext wants [`seal_derived`];
/// a fixed nonce here would repeat across different bodies, and a repeated
/// GCM nonce gives up that nonce's authentication.
pub fn seal_object(
    dek: &Dek,
    nonce: &[u8; 12],
    object_key: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    seal_body(dek, nonce, object_key, &object_body(&compress(plaintext)?)?)
}

/// Seal one object under a nonce derived from what it encrypts.
///
/// `name_input` is the name the object's blinded `object_key` was derived
/// from. Deterministic within a build: the same plaintext at the same name
/// reproduces the same bytes, so a host's listing can be diffed against a
/// fresh seal with no state kept. Not across builds, and it need not be: two
/// versions of the compressor turn one plaintext into two bodies, each gets
/// a nonce of its own, and what differs between them costs a re-upload.
pub fn seal_derived(
    root: &Root,
    dek: &Dek,
    name_input: &str,
    object_key: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    seal_compressed(root, dek, name_input, object_key, &compress(plaintext)?)
}

fn seal_compressed(
    root: &Root,
    dek: &Dek,
    name_input: &str,
    object_key: &str,
    gz: &[u8],
) -> Result<Vec<u8>> {
    let body = object_body(gz)?;
    let nonce = root.object_nonce(name_input, &sha256_hex(&body));
    seal_body(dek, &nonce, object_key, &body)
}

/// Open a frame sealed under `dek` at `object_key`.
pub fn open_object(dek: &Dek, object_key: &str, frame: &[u8]) -> Result<Vec<u8>> {
    use std::io::Read;
    if frame.len() < 16 || &frame[..4] != OBJ_MAGIC {
        return Err(Error::Frame("not a DEP1 frame"));
    }
    let nonce: [u8; 12] = frame[4..16].try_into().expect("sliced 12");
    let cipher = Aes256Gcm::new_from_slice(&dek.0).expect("32-byte key");
    let body = cipher
        .decrypt(
            &Nonce::from(nonce),
            Payload {
                msg: &frame[16..],
                aad: &obj_aad(object_key),
            },
        )
        .map_err(|_| Error::Open)?;
    if body.len() < 4 {
        return Err(Error::Frame("frame body too short"));
    }
    let gz_len = u32::from_le_bytes(body[..4].try_into().expect("sliced 4")) as usize;
    let Some(gz) = body.get(4..4 + gz_len) else {
        return Err(Error::Frame("frame length prefix exceeds body"));
    };
    let mut plaintext = Vec::new();
    flate2::read::GzDecoder::new(gz)
        .read_to_end(&mut plaintext)
        .map_err(|e| Error::Compression(e.to_string()))?;
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padme_buckets_are_monotone_and_bounded() {
        assert_eq!(padme(1), 1);
        assert_eq!(padme(2), 2);
        assert_eq!(padme(9), 10);
        for len in [100usize, 1000, 10_000, 100_000, 1_000_000] {
            let padded = padme(len);
            assert!(padded >= len);
            assert!(padded - len <= len / 8 + 1, "overhead too large at {len}");
        }
        let mut prev = 0;
        for len in 1..4096 {
            let p = padme(len);
            assert!(p >= prev);
            prev = p;
        }
    }

    #[test]
    fn sealed_object_round_trips_and_is_deterministic() {
        let root = Root::mint();
        let keys = root.keys();
        let dek = keys.dek();
        let name = keys.object_key("b4rk9d");
        let plaintext = b"<!doctype html><html>hello</html>".repeat(40);

        let seal = || seal_derived(&root, &dek, "b4rk9d", &name, &plaintext).unwrap();
        let frame = seal();
        assert_eq!(open_object(&dek, &name, &frame).unwrap(), plaintext);
        assert_eq!(seal(), frame);
    }

    /// Two builds compress with different backends, so this is two devices
    /// sealing one unchanged object, not a thought experiment. Under one
    /// nonce a host would hold two GCM ciphertexts of different bodies.
    #[test]
    fn two_compressions_of_one_plaintext_never_share_a_nonce() {
        use std::io::Write;
        let gzip = |level| {
            let mut enc = flate2::write::GzEncoder::new(Vec::new(), level);
            enc.write_all(&b"<p>the same page</p>".repeat(400)).unwrap();
            enc.finish().unwrap()
        };
        let (fast, best) = (
            gzip(flate2::Compression::fast()),
            gzip(flate2::Compression::best()),
        );
        assert_ne!(fast, best);

        let root = Root::mint();
        let keys = root.keys();
        let dek = keys.dek();
        let name = keys.object_key("b4rk9d");
        let one = seal_compressed(&root, &dek, "b4rk9d", &name, &fast).unwrap();
        let two = seal_compressed(&root, &dek, "b4rk9d", &name, &best).unwrap();

        assert_ne!(one[4..16], two[4..16], "two bodies under one nonce");
        assert_eq!(
            open_object(&dek, &name, &one).unwrap(),
            open_object(&dek, &name, &two).unwrap()
        );
    }

    #[test]
    fn sealed_object_is_bound_to_its_name_and_key() {
        let root = Root::mint();
        let keys = root.keys();
        let dek = keys.dek();
        let name = keys.object_key("b4rk9d");
        let nonce = [9u8; 12];
        let frame = seal_object(&dek, &nonce, &name, b"secret page").unwrap();

        let other_name = keys.object_key("x2yq7p");
        assert_eq!(open_object(&dek, &other_name, &frame), Err(Error::Open));
        let other_dek = Root::mint().keys().dek();
        assert_eq!(open_object(&other_dek, &name, &frame), Err(Error::Open));

        let mut tampered = frame.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert_eq!(open_object(&dek, &name, &tampered), Err(Error::Open));
        assert!(matches!(
            open_object(&dek, &name, b"XXXX"),
            Err(Error::Frame(_))
        ));
    }

    #[test]
    fn sealed_sizes_land_on_padme_buckets() {
        let root = Root::mint();
        let keys = root.keys();
        let dek = keys.dek();
        let name = keys.object_key("b4rk9d");
        let nonce = [1u8; 12];
        // The frame's overhead is constant, so equal buckets are equal
        // lengths.
        let a = seal_object(&dek, &nonce, &name, &vec![b'a'; 5000]).unwrap();
        let b = seal_object(&dek, &nonce, &name, &vec![b'a'; 5001]).unwrap();
        assert_eq!(a.len(), b.len());
    }

    /// The frame's layout, at the vector root `[2; 32]` and name `b4rk9d`.
    #[test]
    fn a_frame_is_magic_nonce_and_a_padded_ciphertext() {
        let root = Root::decode("AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI").unwrap();
        let keys = root.keys();
        let dek = keys.dek();
        let name = keys.object_key("b4rk9d");
        assert_eq!(name, "2483a2238d98257737af039fd0436f09");
        let frame = seal_object(&dek, &[7u8; 12], &name, b"hello").unwrap();
        assert_eq!(&frame[..4], b"DEP1");
        assert_eq!(&frame[4..16], &[7u8; 12]);
        let body_len = frame.len() - FRAME_OVERHEAD;
        assert_eq!(body_len, padme(body_len));
        assert_eq!(open_object(&dek, &name, &frame).unwrap(), b"hello");
    }
}
