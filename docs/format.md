# The format (v1)

What sealed-store writes, and what it does and does not claim. Three things consume
these constants today: this crate, diaryx's edge worker, and diaryx's reader
shell in the browser. Every label is prefixed `diaryx-ep-v1/`, where the
format was first written down (diaryx's Encrypted Publishing Spec, Appendices
A and B); a breaking change to any constant is a new prefix, not an edit.

**Status.** Nobody outside the project has reviewed this. The primitives are
standard and the implementations are RustCrypto's; the composition is ours.

## Encodings

Byte strings a person or a URL carries are base64url without padding. Stored
hashes and blinded names are lowercase hex. HKDF is HKDF-SHA-256 with an empty
salt throughout: every input keying material is already uniform, and the
labels carry the separation.

## Gates

A gate is a way in. It derives two values from its secret, apart from each
other, so a host that holds every proof it was ever shown learns nothing about
any KEK.

| | Secret | `proof` | `kek` |
|---|---|---|---|
| Key gate | 32 random bytes | `HKDF(secret, "diaryx-ep-v1/gate-proof", 32)` | `HKDF(secret, "diaryx-ep-v1/gate-kek", 32)` |
| Password gate | chosen by a person | first 32 bytes of the run | last 32 bytes of the run |

The password gate is one Argon2id run (v19) with a 64-byte output. Defaults
are `m = 65536 KiB, t = 3, p = 1` with a 16-byte random salt; salt and costs
are stored beside the gate in the clear, since a reader has to derive before
it can open anything.

`proof` is what a host that controls delivery is shown, and it stores only
`hex(SHA-256(proof))`. `kek` never leaves the device. A vault in a directory
has no such host and does not use the proof.

## Roots and working keys

A root is 32 random bytes that never leave the owner's device except wrapped.

- `dek = HKDF(root, "diaryx-ep-v1/dek", 32)`: content.
- `blind = HKDF(root, "diaryx-ep-v1/blind", 32)`: names.
- `manifest = HKDF(root, "diaryx-ep-v1/manifest", 32)`: reserved.

**Blinded name.** `hex(HMAC-SHA-256(blind, name)[0..16])`. Deterministic, per
root, 128 bits. A reserved name is `0x00 ‖ label`, which no name without a NUL
can collide with.

**Names a reader can derive.** `store_blind = HKDF(dek, "diaryx-ep-v1/store-blind", 32)`
and `hex(HMAC-SHA-256(store_blind, label)[0..16])`, for an object a holder of
the DEK alone has to name before reading anything.

**Wrap.** `nonce(12, random) ‖ AES-256-GCM(kek, nonce, dek)` with AAD
`"diaryx-ep-v1/wrap" ‖ context`, `context` being the name of what the DEK is
for, so a wrap cannot be replayed onto another.

**A key for one job.** `HKDF(dek, info, 32)`, with an `info` of the caller's
under a label of its own.

## Objects

```
frame = "DEP1" ‖ nonce(12) ‖ AES-256-GCM(dek, nonce, body, aad)
aad   = "diaryx-ep-v1/obj" ‖ object_key
body  = u32-le gzip_length ‖ gzip(plaintext) ‖ zero padding
```

The body is padded to the [Padmé](https://petsymposium.org/2019/files/papers/issue4/popets-2019-0056.pdf)
bucket of its unpadded length: at most about 12% more, and less as objects
grow. Compression precedes encryption; the length prefix is what makes the
padding unambiguous to strip.

The nonce is one of two things.

- **Random**, drawn by the caller (`seal_object`).
- **Derived** (`seal_derived`):
  `HKDF(root, "diaryx-ep-v1/nonce" ‖ 0x00 ‖ name ‖ 0x00 ‖ body_hash)[0..12]`,
  `body_hash` being the lowercase-hex SHA-256 of `body`. The same body at the
  same name reproduces the same frame, so a host's listing can be diffed
  against a fresh seal with no state kept. A repeat of the nonce implies an
  identical body, which reproduces the identical ciphertext and nothing else.
  The hash is of the body and not of the plaintext because two compressors
  turn one plaintext into two bodies, and those must not share a nonce.

The nonce rides in the frame because a reader holds the DEK and not the root.

## A vault

A vault is files by path in a store. This layer is sealed-store's own and newer than
the rest; diaryx does not use it.

**Store names.** `vault.json`, `e/<32 hex>`, `c/<32 hex>`.

**Header**, `vault.json`, in the clear:

```json
{
  "vault": 1,
  "id": "<16 random bytes, hex>",
  "gates": [
    {"id": "password", "kind": "password",
     "kdf": {"algo": "argon2id", "m": 65536, "t": 3, "p": 1, "salt": "<b64url>"},
     "wrap": "<b64url>"},
    {"id": "recovery", "kind": "key", "wrap": "<b64url>"}
  ]
}
```

A gate's `wrap` is the vault's **root**, not its DEK:
`nonce(12, random) ‖ AES-256-GCM(kek, nonce, root)` with AAD
`"sealed-store-v1/vault-root" ‖ id`. Whoever opens a vault can name and write files,
which takes the blind key, which takes the root. The id in the AAD keeps a
wrap lifted from one vault's header from opening another's.

**Content**, `c/<key>`: a derived-nonce frame of the file's bytes, with
`name = 0x00 ‖ "c/" ‖ sha256_hex(bytes)` and `key` its blinded name.

**Entry**, `e/<key>`: a derived-nonce frame of the JSON
`{"path": "<path>", "content": "<sha256 hex>", "len": <bytes>}`, with
`name = 0x00 ‖ "e/" ‖ path` and `key` its blinded name. A reader checks that
the path inside an entry blinds to the name it was stored under, and that the
bytes it opens hash to the digest the entry names.

A path is UTF-8 with `/` between its parts, no part empty, `.` or `..`, and no
NUL. There is no index object: listing opens every entry.

Order of writes: content before its entry, a new entry before an old one is
deleted. A stop in between leaves a content object no entry names (`sweep`
removes these) or a file at both of a rename's paths, and never an entry
without its bytes or a file at neither path.

## What a host learns

- How many objects there are, each one's padded length, and when each changes.
- That an object put back as it was is the same object: names and derived
  frames are deterministic. Across roots nothing matches.
- For a vault: how many files there are, which blobs are entries and which
  are content, and how many distinct contents the files have between them.
- A vault's gates: how many, of which kind, and each password gate's salt and
  costs. The header is a complete target for guessing a password offline, as
  any password-opened file on a disk is; the Argon2id costs are the defence.

It does not learn a name, a path, a directory's shape, or a byte of content.

## What is not claimed

- **No binding to a version.** Nothing ties a frame to a moment. A host that
  kept an earlier frame under a name can serve it again, and it opens. A host
  can withhold an object. A vault's entry can be rolled back to an earlier
  one for the same path.
- **A vault's header is not authenticated.** A host can remove a gate from
  it, or put back one that was removed. It cannot add a gate that opens: that
  takes the root.
- **Removing a gate does not re-key.** Whoever opened through it may have
  kept the root. Shutting someone out for good is a new root and everything
  sealed again; diaryx does this for its audiences, and `Vault` does not yet.
- **No read-only way in.** AES-GCM is symmetric: whoever can open an object
  can seal one.
- **AES-GCM under a derived nonce.** The derivation makes a repeat of
  `(key, nonce)` with a different body require an HKDF collision in 96 bits,
  which the birthday bound puts near 2^48 objects under one root. A design
  for strangers' data at scale would use a misuse-resistant AEAD here; v1
  keeps what diaryx's deployed readers open.
- **One message per object.** Sealing and opening hold the whole object in
  memory, a compressed body is at most 4 GiB, and there is no reading a range.

## Test vectors

`src/keys.rs` pins the derivations against values computed with Python's
`hashlib` and `hmac`, and the password gate against the vector diaryx's reader
shell pins (cross-checked there against a C Argon2id). `tests/vectors.rs`
opens a frame and a wrap sealed by `tests/vectors.mjs`, which is Node's
`crypto` and `zlib` and shares no code with this crate.
