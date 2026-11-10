//! Frames sealed by another implementation: `tests/vectors.mjs`, which is
//! Node's `crypto` and `zlib` and holds no RustCrypto and no flate2. What it
//! sealed, this crate opens; if one of these fails, the crate drifted from
//! docs/format.md and not the other way around.
//!
//! `node tests/vectors.mjs` prints them again.

use aril::{GateSecret, Root, derive_link_gate, open_object, unwrap_dek};

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
        "44455031070707070707070707070707573783f1542906ebf2864683959a60b6ea0b4975df0d1679fa891be67362402ec29ecf960c59c8430078fdc4d529590aa2683c8ac2f88180efb4e81251f8b4626f7f09faae5b02a2",
    );
    assert_eq!(
        open_object(&keys.dek(), &name, &frame).unwrap(),
        b"sealed by node, opened by aril\n".repeat(12)
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
