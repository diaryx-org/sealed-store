# sealed-store

A sealed object store for hosts that are not trusted with what they hold: a
synced folder, a bucket, somebody else's server. The host keeps blobs under
names it cannot read. Whoever holds a way in, a password or a key, reads files
by path.

```sh
cargo test                    # the library
cargo run -p sealed-store-gui         # a vault in a window, for trying it by hand
corgi test --workspace        # where corgi is installed: its store is shared with unit and diaryx
```

**It has not been reviewed by anyone outside the project.** The format is
written down in [docs/format.md](docs/format.md) with what it does not claim;
read that before trusting it with anything.

It began as the client half of diaryx's encrypted publishing
(`online/src/publish/crypto.rs` there), and its v1 derivations and frames are
that module's to the byte: what diaryx sealed, sealed-store opens.

## Using it

```rust
use sealed_store::{DirStore, Vault};

let mut vault = Vault::create(DirStore::new("/path/to/synced/folder")?, "correct horse")?;
vault.put("journal/today.md", b"# Today")?;
let recovery = vault.add_key("recovery")?;          // 43 characters, kept nowhere

let vault = Vault::open(DirStore::new("/path/to/synced/folder")?, "correct horse")?;
assert_eq!(vault.get("journal/today.md")?.as_deref(), Some(&b"# Today"[..]));
for file in vault.list()? {
    println!("{} {}", file.len, file.path);
}
```

A `Store` is four methods (`get`, `put`, `delete`, `list`) over named blobs,
and three more with defaults (`size`, `get_range`, `put_with`) that a store
overrides to read and write a large blob a piece at a time.
`DirStore` is a directory and `MemStore` a map; a bucket is one more
implementation.

## What is in it

| Layer | | |
|---|---|---|
| Key material | `Root`, `Keys`, `Dek`, `Kek`, `GateSecret`, `PasswordKdf`, `derive_link_gate`, `derive_password_gate`, `wrap_dek` | A root, the content key and the naming key derived from it, and gates that each wrap the one key. Adding a way in is one small blob; nothing is sealed again. |
| Objects | `seal_object`, `seal_derived`, `open_object`, `padme` | One frame per object: gzip, Padmé padding, AES-256-GCM, bound to its blinded name. `seal_derived` gives the same bytes for the same input, so a listing can be diffed with no state kept. |
| Chunked objects | `seal_stream`, `StreamOpener`, `open_stream`, `ReadAt` | A large object as many AEAD messages (STREAM): constant memory to seal and open, and a range opened from the chunks that hold it. |
| A vault | `Vault`, `Store`, `DirStore`, `MemStore` | Files by path. One sealed entry and one sealed content object per file (chunked past 1 MiB), no shared index, a header with the gates. The `vault` feature, on by default. |

`default-features = false` leaves the first three layers, with no serde: what a
publisher that keeps its own records asks for.

## Beside Cryptomator

sealed-store is not a filesystem and mounts nothing: it is a library an application
calls. It hides more than Cryptomator's vault format does, and does less.

- The store is flat. A host sees how many files there are and each one's
  padded size, and nothing of the directory tree.
- A file's content is named by its digest, so a rename seals only a small
  entry, and two copies of a file are one object.
- A file past 1 MiB is kept chunked: sealed from disk and written back a
  piece at a time, and any range of it read by fetching only the 64 KiB
  chunks that hold it (`put_file`, `get_to`, `read_at`). There is no writing
  into a file: a changed file is sealed again.
- A password, any number of keys, each opening the same vault. Removing one
  does not re-key.

## The GUI

`gui/` is a window over a vault in a directory, built with
[unit](https://github.com/diaryx-org/unit) on Dioxus and drawn by Blitz. It
makes or opens a vault, keeps notes and files, moves and removes them, makes
keys, and shows beside all of it what the directory's keeper sees. It is for
trying the library, and its tests press through it headless.

```sh
SEALED_STORE_VAULT=/tmp/agent-try-sealed-store cargo run -p sealed-store-gui
```

## License

MIT or Apache-2.0, at your option.
