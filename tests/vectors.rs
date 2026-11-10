//! Frames sealed by another implementation: `tests/vectors.mjs`, which is
//! Node's `crypto` and `zlib` and holds no RustCrypto and no flate2. What it
//! sealed, this crate opens; if one of these fails, the crate drifted from
//! docs/format.md and not the other way around.
//!
//! `node tests/vectors.mjs` prints them again.

use sealed_store::{GateSecret, Root, derive_link_gate, open_object, unwrap_dek};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn root() -> Root {
    // base64url of 32 bytes of 0x02.
    Root::decode("AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI").unwrap()
}

#[test]
fn an_object_sealed_by_node_opens() {
    let keys = root().keys();
    let name = keys.object_key("b4rk9d");
    assert_eq!(name, "2483a2238d98257737af039fd0436f09");
    let frame = unhex(
        "444550310707070707070707070707075b3783f1542906ebf2864683959a60b6ea0b4975df0d1679fa891be67362402ec29e072b4e1a366390d8974f9d2c4a9f7764645ebbd712292f902ec5dc457f87576607556153112ee1e78933",
    );
    assert_eq!(
        open_object(&keys.dek(), &name, &frame).unwrap(),
        b"sealed by node, opened in rust\n".repeat(12)
    );
    assert!(open_object(&keys.dek(), &keys.object_key("other"), &frame).is_err());
}

#[test]
fn a_wrap_sealed_by_node_unwraps_to_the_roots_dek() {
    // base64url of 32 bytes of 0x01.
    let secret = GateSecret::from_token("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE").unwrap();
    let kek = derive_link_gate(&secret).kek;
    let wrap = unhex(
        "0909090909090909090909099649f28bd4aa1407902850ea46f827b6648d3e705450244274daa7931ed736062533aeb0d65bc8bcd7d2425423c9a8e3",
    );
    let dek = unwrap_dek(&kek, &wrap, "family").unwrap();
    assert_eq!(dek.fingerprint(), root().keys().dek().fingerprint());
    assert_eq!(dek.fingerprint(), "cdfcf6badf6ef0cbd6778fb59955e72b");
    assert!(unwrap_dek(&kek, &wrap, "partner").is_err());
}

/// A chunked frame holds nothing a second implementation could choose
/// differently (no compressor, no random nonce), so the two are held to the
/// same bytes: 5000 bytes in 1 KiB chunks under a salt of sixteen 0x05.
#[test]
fn a_chunked_frame_is_the_bytes_node_seals() {
    use sealed_store::{open_stream, seal_stream_with, sha256_hex};

    let keys = root().keys();
    let name = keys.object_key("b4rk9d");
    let plain: Vec<u8> = (0..5000usize).map(|i| (i * 7 + (i >> 8)) as u8).collect();
    let mut frame = Vec::new();
    seal_stream_with(
        &keys.dek(),
        &name,
        &[5; 16],
        10,
        plain.len() as u64,
        &plain[..],
        &mut frame,
    )
    .unwrap();
    assert_eq!(frame.len(), 5245);
    assert_eq!(
        frame[..45],
        unhex(
            "444550320a050505050505050505050505050505053a260f2045aaf11d9c79d1b3562cadfe28889e2c0d4c07c6"
        )[..]
    );
    assert_eq!(
        sha256_hex(&frame),
        "bff3e0d230a618c85cf9ee8114e5be6e72d69a2e79c1ed4ed066ad46fa5f8977"
    );
    assert_eq!(open_stream(&keys.dek(), &name, &frame).unwrap(), plain);
}
