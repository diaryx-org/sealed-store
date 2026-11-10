//! The chunked frame: an object sealed and opened a piece at a time.
//!
//! [`crate::seal_object`]'s frame is one AEAD message, held whole in memory.
//! This one is many, so a large object is sealed from a reader and opened to a
//! writer in constant memory, and any range of it is opened by fetching only
//! the chunks that hold it.
//!
//! ```text
//! frame  = "DEP2" ‖ chunk_log2(1) ‖ salt(16) ‖ sealed_len(24) ‖ chunk_0 ‖ … ‖ chunk_n-1
//! key    = HKDF(dek, "diaryx-ep-v1/stream-key" ‖ 0x00 ‖ object_key ‖ 0x00 ‖ chunk_log2 ‖ salt, 32)
//! nonce  = 0x000000 ‖ u64-be counter ‖ flag
//! sealed_len = AES-256-GCM(key, nonce(0, 2), u64-le len, aad)
//! chunk_i    = AES-256-GCM(key, nonce(i, i == n-1), piece_i, aad)
//! aad    = "diaryx-ep-v1/chunk"
//! ```
//!
//! The pieces are the plaintext followed by zeros out to its Padmé bucket, cut
//! every `2^chunk_log2` bytes; an empty object is one empty chunk. Nothing is
//! compressed: what is worth chunking is mostly compressed already, and a
//! range of a compressed stream cannot be opened alone.
//!
//! This is the STREAM construction (Hoang, Reyhanitabar, Rogaway, Vizár,
//! 2015), as `age` and Tink use it. Each object has a key of its own, from a
//! salt, so a counter is a safe nonce. The counter keeps chunks in their
//! order, the flag on the last one keeps the object from being cut short or
//! run on, and the key's derivation binds every chunk to the object's name,
//! its chunk size and its salt. The length is sealed in the header, so a
//! reader knows how many chunks there are, and which is last, before it
//! fetches one.
//!
//! As with the unchunked frame, nothing binds a frame to a version.

use std::io::{Read, Write};

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use rand_core::{OsRng, RngCore};

use crate::error::{Error, Result};
use crate::keys::{Dek, hkdf32};
use crate::object::padme64;

const MAGIC: &[u8; 4] = b"DEP2";
const INFO_KEY: &[u8] = b"diaryx-ep-v1/stream-key";
const AAD: &[u8] = b"diaryx-ep-v1/chunk";
const TAG: u64 = 16;
/// The header's length: magic, chunk size, salt, and the sealed length.
pub const STREAM_HEADER: usize = 4 + 1 + 16 + 8 + 16;

/// The chunk size a sealer uses unless told another: 64 KiB.
pub const CHUNK_LOG2: u8 = 16;
const CHUNK_LOG2_MIN: u8 = 10;
const CHUNK_LOG2_MAX: u8 = 24;

const FLAG_MORE: u8 = 0;
const FLAG_LAST: u8 = 1;
const FLAG_LEN: u8 = 2;

fn nonce(counter: u64, flag: u8) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[3..11].copy_from_slice(&counter.to_be_bytes());
    n[11] = flag;
    n
}

fn cipher(dek: &Dek, object_key: &str, chunk_log2: u8, salt: &[u8; 16]) -> Aes256Gcm {
    let mut info = Vec::with_capacity(INFO_KEY.len() + object_key.len() + 19);
    info.extend_from_slice(INFO_KEY);
    info.push(0);
    info.extend_from_slice(object_key.as_bytes());
    info.push(0);
    info.push(chunk_log2);
    info.extend_from_slice(salt);
    Aes256Gcm::new_from_slice(&hkdf32(&dek.0, &info)).expect("32-byte key")
}

/// How the plaintext of `len` bytes is laid out: (padded length, chunks).
fn layout(len: u64, chunk: u64) -> (u64, u64) {
    let padded = padme64(len);
    (padded, padded.div_ceil(chunk).max(1))
}

/// A salt drawn at random: for a chunked object that need not seal to the
/// same bytes twice. One that must wants [`crate::Root::stream_salt`].
pub fn random_stream_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// The length of the chunked frame of a `len`-byte object, at [`CHUNK_LOG2`].
pub fn sealed_stream_len(len: u64) -> u64 {
    let (padded, chunks) = layout(len, 1 << CHUNK_LOG2);
    STREAM_HEADER as u64 + padded + chunks * TAG
}

/// Whether `frame` begins as a chunked frame does.
pub fn is_stream(frame: &[u8]) -> bool {
    frame.len() >= 4 && &frame[..4] == MAGIC
}

fn io(what: &str, e: std::io::Error) -> Error {
    Error::Io(format!("{what}: {e}"))
}

/// Seal `len` bytes from `reader` into `writer` as a chunked frame at
/// `object_key`, in chunks of [`CHUNK_LOG2`].
///
/// `len` is said first because it is sealed first; a reader that ends before
/// it, or goes on after it, is an error and the frame written is not one.
/// `salt` must never be used twice under one `dek` and `object_key` for
/// different bytes: draw it with [`random_stream_salt`], or derive it from
/// the bytes with [`crate::Root::stream_salt`].
pub fn seal_stream<R: Read, W: Write>(
    dek: &Dek,
    object_key: &str,
    salt: &[u8; 16],
    len: u64,
    reader: R,
    writer: W,
) -> Result<()> {
    seal_stream_with(dek, object_key, salt, CHUNK_LOG2, len, reader, writer)
}

/// [`seal_stream`] in chunks of `2^chunk_log2` bytes, from 1 KiB to 16 MiB.
pub fn seal_stream_with<R: Read, W: Write>(
    dek: &Dek,
    object_key: &str,
    salt: &[u8; 16],
    chunk_log2: u8,
    len: u64,
    mut reader: R,
    mut writer: W,
) -> Result<()> {
    if !(CHUNK_LOG2_MIN..=CHUNK_LOG2_MAX).contains(&chunk_log2) {
        return Err(Error::Frame("chunk size out of range"));
    }
    let chunk = 1u64 << chunk_log2;
    let cipher = cipher(dek, object_key, chunk_log2, salt);
    let (padded, chunks) = layout(len, chunk);

    let mut header = Vec::with_capacity(STREAM_HEADER);
    header.extend_from_slice(MAGIC);
    header.push(chunk_log2);
    header.extend_from_slice(salt);
    header.extend_from_slice(
        &cipher
            .encrypt(
                &Nonce::from(nonce(0, FLAG_LEN)),
                Payload {
                    msg: &len.to_le_bytes(),
                    aad: AAD,
                },
            )
            .map_err(|_| Error::Seal)?,
    );
    writer.write_all(&header).map_err(|e| io("writing", e))?;

    let mut piece = vec![0u8; chunk as usize];
    for i in 0..chunks {
        let start = i * chunk;
        let size = (padded - start).min(chunk) as usize;
        // The part of this piece that is the object's; the rest is padding.
        let data = (len.saturating_sub(start)).min(size as u64) as usize;
        reader.read_exact(&mut piece[..data]).map_err(|e| {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                Error::Io("what was to be sealed ended before its length".to_string())
            } else {
                io("reading", e)
            }
        })?;
        piece[data..size].fill(0);
        let flag = if i == chunks - 1 {
            FLAG_LAST
        } else {
            FLAG_MORE
        };
        let ct = cipher
            .encrypt(
                &Nonce::from(nonce(i, flag)),
                Payload {
                    msg: &piece[..size],
                    aad: AAD,
                },
            )
            .map_err(|_| Error::Seal)?;
        writer.write_all(&ct).map_err(|e| io("writing", e))?;
    }
    let mut one = [0u8; 1];
    match reader.read(&mut one) {
        Ok(0) => {}
        Ok(_) => {
            return Err(Error::Io(
                "what was to be sealed went on past its length".to_string(),
            ));
        }
        Err(e) => return Err(io("reading", e)),
    }
    writer.flush().map_err(|e| io("writing", e))
}

/// Where a chunked frame is read from, a range at a time: bytes in memory, a
/// file, or a host that answers range requests.
pub trait ReadAt {
    /// Fill `buf` from `offset`. Fewer bytes than `buf` holds is an error.
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()>;
}

impl ReadAt for [u8] {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let from = usize::try_from(offset)
            .ok()
            .and_then(|start| self.get(start..)?.get(..buf.len()))
            .ok_or(Error::Frame("chunked frame is cut short"))?;
        buf.copy_from_slice(from);
        Ok(())
    }
}

impl ReadAt for Vec<u8> {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.as_slice().read_exact_at(offset, buf)
    }
}

impl<T: ReadAt + ?Sized> ReadAt for &T {
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        (**self).read_exact_at(offset, buf)
    }
}

/// A chunked frame, opened: its length known, and any range of it readable.
pub struct StreamOpener<R: ReadAt> {
    source: R,
    cipher: Aes256Gcm,
    chunk: u64,
    len: u64,
    padded: u64,
    chunks: u64,
}

impl<R: ReadAt> StreamOpener<R> {
    /// Open the chunked frame in `source`, sealed under `dek` at
    /// `object_key`. Reads the header and nothing else.
    ///
    /// `sealed_len` is the frame's length in bytes where the caller knows it,
    /// as a store does; a frame of any other length than its header's is
    /// refused here, before a chunk is read.
    pub fn open(dek: &Dek, object_key: &str, source: R, sealed_len: Option<u64>) -> Result<Self> {
        let mut header = [0u8; STREAM_HEADER];
        source.read_exact_at(0, &mut header)?;
        if &header[..4] != MAGIC {
            return Err(Error::Frame("not a DEP2 frame"));
        }
        let chunk_log2 = header[4];
        if !(CHUNK_LOG2_MIN..=CHUNK_LOG2_MAX).contains(&chunk_log2) {
            return Err(Error::Frame("chunk size out of range"));
        }
        let salt: [u8; 16] = header[5..21].try_into().expect("sliced 16");
        let cipher = cipher(dek, object_key, chunk_log2, &salt);
        let len = cipher
            .decrypt(
                &Nonce::from(nonce(0, FLAG_LEN)),
                Payload {
                    msg: &header[21..],
                    aad: AAD,
                },
            )
            .map_err(|_| Error::Open)?;
        let len = u64::from_le_bytes(len.try_into().map_err(|_| Error::Open)?);
        let chunk = 1u64 << chunk_log2;
        let (padded, chunks) = layout(len, chunk);
        if sealed_len.is_some_and(|n| n != STREAM_HEADER as u64 + padded + chunks * TAG) {
            return Err(Error::Frame("chunked frame is not the length it says"));
        }
        Ok(Self {
            source,
            cipher,
            chunk,
            len,
            padded,
            chunks,
        })
    }

    /// The object's length in bytes.
    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The plaintext of chunk `i`, padding and all.
    fn piece(&self, i: u64) -> Result<Vec<u8>> {
        let start = i * self.chunk;
        let size = (self.padded - start).min(self.chunk);
        let mut ct = vec![0u8; (size + TAG) as usize];
        self.source
            .read_exact_at(STREAM_HEADER as u64 + i * (self.chunk + TAG), &mut ct)?;
        let flag = if i == self.chunks - 1 {
            FLAG_LAST
        } else {
            FLAG_MORE
        };
        self.cipher
            .decrypt(&Nonce::from(nonce(i, flag)), Payload { msg: &ct, aad: AAD })
            .map_err(|_| Error::Open)
    }

    /// Read into `buf` from `offset` in the object, opening only the chunks
    /// that hold those bytes. Returns how many were read: fewer than `buf`
    /// holds only at the object's end, and none past it.
    pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if offset >= self.len {
            return Ok(0);
        }
        let want = (buf.len() as u64).min(self.len - offset) as usize;
        let mut done = 0;
        while done < want {
            let at = offset + done as u64;
            let piece = self.piece(at / self.chunk)?;
            let within = (at % self.chunk) as usize;
            let take = (want - done).min(piece.len() - within);
            buf[done..done + take].copy_from_slice(&piece[within..within + take]);
            done += take;
        }
        Ok(want)
    }

    /// Write the whole object to `writer`, a chunk at a time.
    ///
    /// Each chunk is authenticated before a byte of it is written, but the
    /// object is whole only when this returns `Ok`: a frame cut short writes
    /// its first chunks and then fails.
    pub fn copy_to<W: Write>(&self, mut writer: W) -> Result<()> {
        let mut left = self.len;
        for i in 0..self.chunks {
            let piece = self.piece(i)?;
            let take = left.min(piece.len() as u64) as usize;
            writer
                .write_all(&piece[..take])
                .map_err(|e| io("writing", e))?;
            left -= take as u64;
        }
        writer.flush().map_err(|e| io("writing", e))
    }
}

/// Open a whole chunked frame held in memory.
pub fn open_stream(dek: &Dek, object_key: &str, frame: &[u8]) -> Result<Vec<u8>> {
    let opener = StreamOpener::open(dek, object_key, frame, Some(frame.len() as u64))?;
    let mut out = Vec::with_capacity(opener.len() as usize);
    opener.copy_to(&mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{Root, sha256_hex};

    fn keys() -> (Root, Dek, String) {
        let root = Root::mint();
        let keys = root.keys();
        (root.clone(), keys.dek(), keys.object_key("film.mov"))
    }

    /// Bytes that do not repeat at any chunk's period.
    fn bytes(len: usize) -> Vec<u8> {
        (0..len as u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
            .collect()
    }

    fn seal(dek: &Dek, name: &str, log2: u8, plain: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        seal_stream_with(
            dek,
            name,
            &[5; 16],
            log2,
            plain.len() as u64,
            plain,
            &mut frame,
        )
        .unwrap();
        frame
    }

    #[test]
    fn every_length_around_a_chunks_edge_round_trips() {
        let (_, dek, name) = keys();
        for len in [0, 1, 2, 1023, 1024, 1025, 2047, 2048, 2049, 5000, 70_000] {
            let plain = bytes(len);
            let frame = seal(&dek, &name, 10, &plain);
            assert_eq!(open_stream(&dek, &name, &frame).unwrap(), plain, "{len}");
            let (padded, chunks) = layout(len as u64, 1024);
            assert_eq!(
                frame.len() as u64,
                STREAM_HEADER as u64 + padded + chunks * TAG,
                "{len}"
            );
        }
    }

    #[test]
    fn the_default_chunk_is_64_kib_and_its_length_is_foretold() {
        let (_, dek, name) = keys();
        let plain = bytes(200_000);
        let mut frame = Vec::new();
        seal_stream(&dek, &name, &[5; 16], 200_000, &plain[..], &mut frame).unwrap();
        assert_eq!(frame.len() as u64, sealed_stream_len(200_000));
        assert_eq!(frame[4], 16);
        assert!(is_stream(&frame));
        assert_eq!(open_stream(&dek, &name, &frame).unwrap(), plain);
    }

    /// A source that counts what is asked of it.
    struct Counting<'a>(&'a [u8], std::cell::RefCell<Vec<(u64, usize)>>);
    impl ReadAt for Counting<'_> {
        fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
            self.1.borrow_mut().push((offset, buf.len()));
            self.0.read_exact_at(offset, buf)
        }
    }

    #[test]
    fn a_range_opens_only_the_chunks_that_hold_it() {
        let (_, dek, name) = keys();
        let plain = bytes(10_000);
        let frame = seal(&dek, &name, 10, &plain);
        let source = Counting(&frame, Default::default());
        let opener = StreamOpener::open(&dek, &name, &source, Some(frame.len() as u64)).unwrap();
        assert_eq!(opener.len(), 10_000);
        assert_eq!(source.1.borrow().len(), 1, "the header and nothing else");

        // Bytes 2100..2200 lie in chunk 2 alone; 4090..4100 in chunks 3 and 4.
        let mut buf = [0u8; 100];
        assert_eq!(opener.read_at(2100, &mut buf).unwrap(), 100);
        assert_eq!(buf, plain[2100..2200]);
        let mut buf = [0u8; 10];
        assert_eq!(opener.read_at(4090, &mut buf).unwrap(), 10);
        assert_eq!(buf, plain[4090..4100]);
        let asked = source.1.borrow();
        let chunk = |i: u64| (STREAM_HEADER as u64 + i * 1040, 1040usize);
        assert_eq!(asked[1..], [chunk(2), chunk(3), chunk(4)]);
    }

    #[test]
    fn a_read_at_the_end_is_short_and_past_it_is_nothing() {
        let (_, dek, name) = keys();
        let plain = bytes(2500);
        let frame = seal(&dek, &name, 10, &plain);
        let opener = StreamOpener::open(&dek, &name, &frame[..], None).unwrap();
        let mut buf = [0xAAu8; 100];
        // The padding after the last byte is never handed out.
        assert_eq!(opener.read_at(2450, &mut buf).unwrap(), 50);
        assert_eq!(buf[..50], plain[2450..]);
        assert_eq!(opener.read_at(2500, &mut buf).unwrap(), 0);
        assert_eq!(opener.read_at(9999, &mut buf).unwrap(), 0);
    }

    #[test]
    fn it_opens_under_no_other_key_name_or_chunk() {
        let (_, dek, name) = keys();
        let plain = bytes(5000);
        let frame = seal(&dek, &name, 10, &plain);
        let (_, other_dek, _) = keys();
        assert!(matches!(
            open_stream(&other_dek, &name, &frame),
            Err(Error::Open)
        ));
        assert!(matches!(
            open_stream(&dek, "another-name", &frame),
            Err(Error::Open)
        ));
        // The chunk size in the clear, changed: another key, so nothing opens.
        let mut resized = frame.clone();
        resized[4] = 11;
        assert!(open_stream(&dek, &name, &resized).is_err());
        let mut salted = frame.clone();
        salted[5] ^= 1;
        assert!(matches!(
            open_stream(&dek, &name, &salted),
            Err(Error::Open)
        ));
        assert!(matches!(
            open_stream(
                &dek,
                &name,
                b"DEP1 and then some more bytes to be long enough....."
            ),
            Err(Error::Frame(_))
        ));
    }

    /// The frame's chunks, as ranges of it.
    fn chunk_ranges(frame: &[u8], chunk: usize) -> Vec<std::ops::Range<usize>> {
        let mut out = Vec::new();
        let mut at = STREAM_HEADER;
        while at < frame.len() {
            let end = (at + chunk + 16).min(frame.len());
            out.push(at..end);
            at = end;
        }
        out
    }

    #[test]
    fn chunks_cut_off_swapped_repeated_or_changed_do_not_open() {
        let (_, dek, name) = keys();
        let plain = bytes(4096);
        let frame = seal(&dek, &name, 10, &plain);
        let ranges = chunk_ranges(&frame, 1024);
        assert_eq!(ranges.len(), 4);
        let open = |frame: &[u8]| {
            StreamOpener::open(&dek, &name, frame, None).and_then(|o| {
                let mut out = Vec::new();
                o.copy_to(&mut out).map(|()| out)
            })
        };
        assert_eq!(open(&frame).unwrap(), plain);

        // Cut after the third chunk: with its length known it is refused at
        // the door, and without, when the fourth is asked for.
        let cut = &frame[..ranges[2].end];
        assert!(matches!(
            StreamOpener::open(&dek, &name, cut, Some(cut.len() as u64)),
            Err(Error::Frame(_))
        ));
        assert!(matches!(open(cut), Err(Error::Frame(_))));

        // Two chunks changed places.
        let mut swapped = frame.clone();
        let (a, b) = (
            frame[ranges[0].clone()].to_vec(),
            frame[ranges[1].clone()].to_vec(),
        );
        swapped[ranges[0].clone()].copy_from_slice(&b);
        swapped[ranges[1].clone()].copy_from_slice(&a);
        assert!(matches!(open(&swapped), Err(Error::Open)));

        // The third chunk served as the last: an object cut short and
        // dressed as whole.
        let mut dressed = frame.clone();
        dressed[ranges[3].clone()].copy_from_slice(&frame[ranges[2].clone()]);
        assert!(matches!(open(&dressed), Err(Error::Open)));

        // One bit of one chunk.
        let mut flipped = frame.clone();
        flipped[ranges[1].start + 7] ^= 1;
        assert!(matches!(open(&flipped), Err(Error::Open)));
        // And a range that does not touch that chunk still opens.
        let opener = StreamOpener::open(&dek, &name, &flipped[..], None).unwrap();
        let mut buf = [0u8; 16];
        assert_eq!(opener.read_at(3000, &mut buf).unwrap(), 16);
        assert_eq!(buf, plain[3000..3016]);
        assert!(matches!(opener.read_at(1500, &mut buf), Err(Error::Open)));

        // The sealed length changed.
        let mut relength = frame.clone();
        relength[25] ^= 1;
        assert!(matches!(open(&relength), Err(Error::Open)));
    }

    #[test]
    fn a_reader_shorter_or_longer_than_its_length_is_refused() {
        let (_, dek, name) = keys();
        let plain = bytes(3000);
        let mut out = Vec::new();
        assert!(matches!(
            seal_stream(&dek, &name, &[5; 16], 3001, &plain[..], &mut out),
            Err(Error::Io(_))
        ));
        let mut out = Vec::new();
        assert!(matches!(
            seal_stream(&dek, &name, &[5; 16], 2999, &plain[..], &mut out),
            Err(Error::Io(_))
        ));
        for log2 in [9, 25] {
            assert!(matches!(
                seal_stream_with(
                    &dek,
                    &name,
                    &[5; 16],
                    log2,
                    3000,
                    &plain[..],
                    &mut Vec::new()
                ),
                Err(Error::Frame(_))
            ));
        }
    }

    #[test]
    fn a_derived_salt_seals_the_same_bytes_the_same_and_others_otherwise() {
        let (root, dek, name) = keys();
        let seal = |plain: &[u8]| {
            let salt = root.stream_salt("film.mov", &sha256_hex(plain));
            let mut frame = Vec::new();
            seal_stream(&dek, &name, &salt, plain.len() as u64, plain, &mut frame).unwrap();
            frame
        };
        let (one, two) = (bytes(3000), bytes(3001));
        assert_eq!(seal(&one), seal(&one));
        let (a, b) = (seal(&one), seal(&two));
        assert_ne!(a[5..21], b[5..21], "other bytes, another salt and key");
        assert_ne!(
            root.stream_salt("film.mov", &sha256_hex(&one)),
            root.stream_salt("other.mov", &sha256_hex(&one))
        );
        assert_ne!(random_stream_salt(), random_stream_salt());
    }

    #[test]
    fn the_sealed_length_hides_the_true_one_in_its_bucket() {
        let (_, dek, name) = keys();
        let a = seal(&dek, &name, 10, &bytes(5000));
        let b = seal(&dek, &name, 10, &bytes(5001));
        assert_eq!(a.len(), b.len());
    }
}
