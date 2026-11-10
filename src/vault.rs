//! A vault: files by path, kept in a [`Store`] that learns neither their
//! names nor their contents.
//!
//! Built from the primitives and nothing else (docs/format.md, "A vault"):
//!
//! - `vault.json`, in the clear: the vault's id and its gates, each a way in
//!   that wraps the vault's [`Root`].
//! - `c/<name>`: a file's bytes, sealed, named by the digest of the bytes. A
//!   file kept twice is one object, and a renamed file is not sealed again.
//! - `e/<name>`: one entry per file, sealed, named by its path: the path, and
//!   the digest and length of its bytes.
//!
//! There is no index object. Each file is an entry and a content object of
//! its own, so two devices that add two files through a synced folder never
//! write the same blob, and a listing opens the entries.
//!
//! What a store learns: how many files there are, each one's padded size,
//! when each changes, and that a file put back as it was is the same file.
//! What it can do unnoticed: serve an earlier entry for a path, or withhold
//! one, since nothing binds a frame to a version.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::keys::{
    Dek, GateSecret, Kek, Keys, PasswordKdf, Root, derive_link_gate, derive_password_gate, hex,
    reserved_name, sha256_hex,
};
use crate::object::{open_object, seal_derived};
use crate::store::Store;

/// The header's name in the store.
pub const HEADER: &str = "vault.json";
const VERSION: u32 = 1;
const AAD_ROOT: &[u8] = b"sealed-store-v1/vault-root";
const ENTRIES: &str = "e";
const CONTENTS: &str = "c";

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Header {
    vault: u32,
    /// 16 random bytes, hex: bound into every gate's wrap, so a wrap lifted
    /// from one vault's header opens nothing in another's.
    id: String,
    gates: Vec<GateRecord>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct GateRecord {
    id: String,
    #[serde(flatten)]
    kind: GateKind,
    /// The vault's root under this gate's KEK, base64url.
    wrap: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum GateKind {
    Password { kdf: KdfRecord },
    Key,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct KdfRecord {
    algo: String,
    m: u32,
    t: u32,
    p: u32,
    salt: String,
}

impl KdfRecord {
    fn of(kdf: &PasswordKdf) -> Self {
        Self {
            algo: "argon2id".to_string(),
            m: kdf.m_kib,
            t: kdf.t_cost,
            p: kdf.p_cost,
            salt: kdf.salt_b64(),
        }
    }

    fn kdf(&self) -> Result<PasswordKdf> {
        if self.algo != "argon2id" {
            return Err(Error::Vault(format!(
                "a password gate derived with {:?}, which this build does not know",
                self.algo
            )));
        }
        PasswordKdf::from_stored(self.m, self.t, self.p, &self.salt)
    }
}

/// A way into a vault, as its header lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gate {
    pub id: String,
    pub kind: GateType,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateType {
    /// Opened by a password, stretched with Argon2id.
    Password,
    /// Opened by a 32-byte secret: a recovery key, or a key for one device.
    Key,
}

#[derive(Serialize, Deserialize)]
struct EntryRecord {
    path: String,
    /// Lowercase-hex SHA-256 of the file's bytes.
    content: String,
    len: u64,
}

/// A file in a vault.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub path: String,
    /// The file's length in bytes, before it was compressed and sealed.
    pub len: u64,
    /// Lowercase-hex SHA-256 of the file's bytes.
    pub digest: String,
}

/// A blob as the store holds it: all that whoever keeps the store can see.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Held {
    pub name: String,
    pub len: u64,
}

/// An open vault over a store.
pub struct Vault<S: Store> {
    store: S,
    header: Header,
    root: Root,
    keys: Keys,
    dek: Dek,
}

fn header_of<S: Store>(store: &S) -> Result<Option<Header>> {
    let Some(bytes) = store.get(HEADER)? else {
        return Ok(None);
    };
    let header: Header = serde_json::from_slice(&bytes)
        .map_err(|e| Error::Vault(format!("{HEADER} is not a vault's header: {e}")))?;
    if header.vault != VERSION {
        return Err(Error::Vault(format!(
            "a vault of version {}, and this build reads version {VERSION}",
            header.vault
        )));
    }
    Ok(Some(header))
}

fn root_aad(vault_id: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_ROOT.len() + vault_id.len());
    aad.extend_from_slice(AAD_ROOT);
    aad.extend_from_slice(vault_id.as_bytes());
    aad
}

fn wrap_root(kek: &Kek, vault_id: &str, root: &Root) -> Result<String> {
    Ok(URL_SAFE_NO_PAD.encode(kek.seal(&root_aad(vault_id), &root.0)?))
}

fn unwrap_root(kek: &Kek, vault_id: &str, wrap: &str) -> Option<Root> {
    let blob = URL_SAFE_NO_PAD.decode(wrap).ok()?;
    let bytes = kek.open(&root_aad(vault_id), &blob).ok()?;
    Some(Root(bytes.try_into().ok()?))
}

/// A path as a vault keeps it: `/` between its parts, and no part empty, `.`
/// or `..`. Not a path on any disk, so nothing in it can climb.
fn check_path(path: &str) -> Result<()> {
    let ok = !path.is_empty()
        && !path.contains('\0')
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..");
    if ok {
        Ok(())
    } else {
        Err(Error::Vault(format!("not a path in a vault: {path:?}")))
    }
}

fn is_blinded(leaf: &str) -> bool {
    leaf.len() == 32 && leaf.bytes().all(|b| b.is_ascii_hexdigit())
}

impl<S: Store> Vault<S> {
    /// Make a vault in an empty store, with one gate: `password`, stretched
    /// at [`crate::PASSWORD_KDF_DEFAULTS`].
    pub fn create(store: S, password: &str) -> Result<Self> {
        Self::create_with(store, password, PasswordKdf::mint())
    }

    /// [`Vault::create`] with Argon2id costs of the caller's choosing.
    pub fn create_with(store: S, password: &str, kdf: PasswordKdf) -> Result<Self> {
        if store.get(HEADER)?.is_some() {
            return Err(Error::Vault("there is a vault here already".to_string()));
        }
        let mut id = [0u8; 16];
        OsRng.fill_bytes(&mut id);
        let id = hex(&id);
        let root = Root::mint();
        let kek = derive_password_gate(password, &kdf)?.kek;
        let header = Header {
            vault: VERSION,
            gates: vec![GateRecord {
                id: "password".to_string(),
                kind: GateKind::Password {
                    kdf: KdfRecord::of(&kdf),
                },
                wrap: wrap_root(&kek, &id, &root)?,
            }],
            id,
        };
        let vault = Self::with(store, header, root);
        vault.write_header()?;
        Ok(vault)
    }

    /// Whether `store` holds a vault's header.
    pub fn exists(store: &S) -> Result<bool> {
        Ok(store.get(HEADER)?.is_some())
    }

    /// Open the vault in `store` with a password. One Argon2id run for each
    /// password gate with costs or a salt of its own.
    pub fn open(store: S, password: &str) -> Result<Self> {
        let header =
            header_of(&store)?.ok_or_else(|| Error::Vault("there is no vault here".to_string()))?;
        let mut tried: Vec<(PasswordKdf, Kek)> = Vec::new();
        let mut root = None;
        for gate in &header.gates {
            let GateKind::Password { kdf } = &gate.kind else {
                continue;
            };
            let kdf = kdf.kdf()?;
            let at = match tried.iter().position(|(k, _)| *k == kdf) {
                Some(at) => at,
                None => {
                    let kek = derive_password_gate(password, &kdf)?.kek;
                    tried.push((kdf, kek));
                    tried.len() - 1
                }
            };
            if let Some(found) = unwrap_root(&tried[at].1, &header.id, &gate.wrap) {
                root = Some(found);
                break;
            }
        }
        let root = root.ok_or(Error::Open)?;
        Ok(Self::with(store, header, root))
    }

    /// Open the vault in `store` with a key [`Vault::add_key`] gave.
    pub fn open_with_key(store: S, key: &str) -> Result<Self> {
        let header =
            header_of(&store)?.ok_or_else(|| Error::Vault("there is no vault here".to_string()))?;
        let kek = derive_link_gate(&GateSecret::from_token(key.trim())?).kek;
        let root = header
            .gates
            .iter()
            .filter(|gate| matches!(gate.kind, GateKind::Key))
            .find_map(|gate| unwrap_root(&kek, &header.id, &gate.wrap))
            .ok_or(Error::Open)?;
        Ok(Self::with(store, header, root))
    }

    fn with(store: S, header: Header, root: Root) -> Self {
        let keys = root.keys();
        let dek = keys.dek();
        Self {
            store,
            header,
            root,
            keys,
            dek,
        }
    }

    fn write_header(&self) -> Result<()> {
        let mut bytes = serde_json::to_vec_pretty(&self.header)
            .map_err(|e| Error::Vault(format!("writing {HEADER}: {e}")))?;
        bytes.push(b'\n');
        self.store.put(HEADER, &bytes)
    }

    /// The vault's id: 16 random bytes, hex, in its header in the clear.
    pub fn id(&self) -> &str {
        &self.header.id
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    /// The ways in, as the header lists them.
    pub fn gates(&self) -> Vec<Gate> {
        self.header
            .gates
            .iter()
            .map(|gate| Gate {
                id: gate.id.clone(),
                kind: match gate.kind {
                    GateKind::Password { .. } => GateType::Password,
                    GateKind::Key => GateType::Key,
                },
            })
            .collect()
    }

    fn check_new_gate(&self, id: &str) -> Result<()> {
        if id.is_empty() || id.len() > 64 || id.chars().any(char::is_control) {
            return Err(Error::Vault(format!("not a gate's id: {id:?}")));
        }
        if self.header.gates.iter().any(|gate| gate.id == id) {
            return Err(Error::Vault(format!("there is a gate {id:?} already")));
        }
        Ok(())
    }

    /// Add a way in that needs no password: a fresh 32-byte secret, returned
    /// as base64url and kept nowhere. A recovery key to write down, or a key
    /// for one device. It opens the vault through [`Vault::open_with_key`].
    pub fn add_key(&mut self, id: &str) -> Result<String> {
        self.check_new_gate(id)?;
        let secret = GateSecret::mint();
        let kek = derive_link_gate(&secret).kek;
        self.header.gates.push(GateRecord {
            id: id.to_string(),
            kind: GateKind::Key,
            wrap: wrap_root(&kek, &self.header.id, &self.root)?,
        });
        self.write_header()?;
        Ok(secret.token())
    }

    /// Replace every password gate with one for `password`.
    pub fn set_password(&mut self, password: &str) -> Result<()> {
        self.set_password_with(password, PasswordKdf::mint())
    }

    /// [`Vault::set_password`] with Argon2id costs of the caller's choosing.
    pub fn set_password_with(&mut self, password: &str, kdf: PasswordKdf) -> Result<()> {
        let kek = derive_password_gate(password, &kdf)?.kek;
        let gate = GateRecord {
            id: "password".to_string(),
            kind: GateKind::Password {
                kdf: KdfRecord::of(&kdf),
            },
            wrap: wrap_root(&kek, &self.header.id, &self.root)?,
        };
        self.header
            .gates
            .retain(|gate| !matches!(gate.kind, GateKind::Password { .. }));
        self.header.gates.insert(0, gate);
        self.write_header()
    }

    /// Take a way in out of the header. The last one stays.
    ///
    /// This closes the gate and does not change the lock: whoever opened the
    /// vault through it may have kept the root, and a copy of the old header
    /// still opens the vault with the old secret. Shutting someone out for
    /// good is a new vault and the files sealed again.
    pub fn remove_gate(&mut self, id: &str) -> Result<()> {
        if !self.header.gates.iter().any(|gate| gate.id == id) {
            return Err(Error::Vault(format!("there is no gate {id:?}")));
        }
        if self.header.gates.len() == 1 {
            return Err(Error::Vault(
                "a vault's last gate stays: without one nothing opens it".to_string(),
            ));
        }
        self.header.gates.retain(|gate| gate.id != id);
        self.write_header()
    }

    fn entry_name(&self, path: &str) -> (String, String) {
        let label = reserved_name(&format!("e/{path}"));
        let key = self.keys.object_key(&label);
        (label, key)
    }

    fn content_name(&self, digest: &str) -> (String, String) {
        let label = reserved_name(&format!("c/{digest}"));
        let key = self.keys.object_key(&label);
        (label, key)
    }

    fn read_entry(&self, key: &str) -> Result<Option<EntryRecord>> {
        let Some(frame) = self.store.get(&format!("{ENTRIES}/{key}"))? else {
            return Ok(None);
        };
        let plain = open_object(&self.dek, key, &frame)?;
        let record: EntryRecord = serde_json::from_slice(&plain)
            .map_err(|e| Error::Store(format!("entry {key} is not an entry: {e}")))?;
        // The AAD says the frame was sealed for this name; this says the path
        // inside it is the one the name was derived from.
        if check_path(&record.path).is_err() || self.entry_name(&record.path).1 != key {
            return Err(Error::Store(format!("entry {key} names another path")));
        }
        Ok(Some(record))
    }

    /// Keep `bytes` at `path`, replacing what was there.
    pub fn put(&self, path: &str, bytes: &[u8]) -> Result<()> {
        check_path(path)?;
        let digest = sha256_hex(bytes);
        let (c_label, c_key) = self.content_name(&digest);
        let c_name = format!("{CONTENTS}/{c_key}");
        // The content first: an entry never names an object that is not there.
        if self.store.get(&c_name)?.is_none() {
            let frame = seal_derived(&self.root, &self.dek, &c_label, &c_key, bytes)?;
            self.store.put(&c_name, &frame)?;
        }
        let (e_label, e_key) = self.entry_name(path);
        let was = self.read_entry(&e_key).ok().flatten().map(|e| e.content);
        let record = EntryRecord {
            path: path.to_string(),
            content: digest.clone(),
            len: bytes.len() as u64,
        };
        let plain = serde_json::to_vec(&record)
            .map_err(|e| Error::Vault(format!("writing an entry: {e}")))?;
        let frame = seal_derived(&self.root, &self.dek, &e_label, &e_key, &plain)?;
        self.store.put(&format!("{ENTRIES}/{e_key}"), &frame)?;
        if let Some(was) = was.filter(|was| *was != digest) {
            self.drop_content_unless_kept(&was)?;
        }
        Ok(())
    }

    /// The bytes at `path`, or `None` where the vault has no such file.
    pub fn get(&self, path: &str) -> Result<Option<Vec<u8>>> {
        check_path(path)?;
        let (_, e_key) = self.entry_name(path);
        let Some(record) = self.read_entry(&e_key)? else {
            return Ok(None);
        };
        let (_, c_key) = self.content_name(&record.content);
        let frame = self
            .store
            .get(&format!("{CONTENTS}/{c_key}"))?
            .ok_or_else(|| Error::Store(format!("the bytes of {path:?} are missing")))?;
        let bytes = open_object(&self.dek, &c_key, &frame)?;
        if sha256_hex(&bytes) != record.content {
            return Err(Error::Store(format!(
                "the bytes of {path:?} are not the ones its entry names"
            )));
        }
        Ok(Some(bytes))
    }

    /// Every file, in path order. Opens every entry.
    pub fn list(&self) -> Result<Vec<Entry>> {
        let mut out = Vec::new();
        for (leaf, _) in self.store.list(ENTRIES)? {
            if !is_blinded(&leaf) {
                continue;
            }
            if let Some(record) = self.read_entry(&leaf)? {
                out.push(Entry {
                    path: record.path,
                    len: record.len,
                    digest: record.content,
                });
            }
        }
        out.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(out)
    }

    /// Remove the file at `path`. `false` where there was none.
    pub fn remove(&self, path: &str) -> Result<bool> {
        check_path(path)?;
        let (_, e_key) = self.entry_name(path);
        let Some(record) = self.read_entry(&e_key)? else {
            return Ok(false);
        };
        self.store.delete(&format!("{ENTRIES}/{e_key}"))?;
        self.drop_content_unless_kept(&record.content)?;
        Ok(true)
    }

    /// Move the file at `from` to `to`, replacing what was there. Its bytes
    /// are not sealed again: only its entry is. `false` where there was no
    /// file at `from`.
    pub fn rename(&self, from: &str, to: &str) -> Result<bool> {
        check_path(from)?;
        check_path(to)?;
        if from == to {
            return Ok(self.read_entry(&self.entry_name(from).1)?.is_some());
        }
        let (_, from_key) = self.entry_name(from);
        let Some(record) = self.read_entry(&from_key)? else {
            return Ok(false);
        };
        let (to_label, to_key) = self.entry_name(to);
        let replaced = self.read_entry(&to_key).ok().flatten().map(|e| e.content);
        let moved = EntryRecord {
            path: to.to_string(),
            content: record.content.clone(),
            len: record.len,
        };
        let plain = serde_json::to_vec(&moved)
            .map_err(|e| Error::Vault(format!("writing an entry: {e}")))?;
        let frame = seal_derived(&self.root, &self.dek, &to_label, &to_key, &plain)?;
        // The new entry before the old one goes: a stop between the two
        // leaves the file at both paths, and never at neither.
        self.store.put(&format!("{ENTRIES}/{to_key}"), &frame)?;
        self.store.delete(&format!("{ENTRIES}/{from_key}"))?;
        if let Some(replaced) = replaced.filter(|d| *d != record.content) {
            self.drop_content_unless_kept(&replaced)?;
        }
        Ok(true)
    }

    /// Delete the content object for `digest` unless an entry still names it.
    fn drop_content_unless_kept(&self, digest: &str) -> Result<()> {
        if self.list()?.iter().any(|entry| entry.digest == digest) {
            return Ok(());
        }
        let (_, c_key) = self.content_name(digest);
        self.store.delete(&format!("{CONTENTS}/{c_key}"))
    }

    /// Delete every content object no entry names: what a stop between a
    /// put's two writes, or two devices' writes through a synced folder, can
    /// leave behind. Returns how many went.
    pub fn sweep(&self) -> Result<usize> {
        let kept: std::collections::BTreeSet<String> = self
            .list()?
            .iter()
            .map(|entry| self.content_name(&entry.digest).1)
            .collect();
        let mut gone = 0;
        for (leaf, _) in self.store.list(CONTENTS)? {
            if is_blinded(&leaf) && !kept.contains(&leaf) {
                self.store.delete(&format!("{CONTENTS}/{leaf}"))?;
                gone += 1;
            }
        }
        Ok(gone)
    }

    /// Every blob in the store, as whoever keeps the store sees it: names
    /// and lengths.
    pub fn held(&self) -> Result<Vec<Held>> {
        let mut out = Vec::new();
        for dir in ["", ENTRIES, CONTENTS] {
            for (leaf, len) in self.store.list(dir)? {
                let name = if dir.is_empty() {
                    leaf
                } else {
                    format!("{dir}/{leaf}")
                };
                out.push(Held { name, len });
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemStore;

    fn cheap() -> PasswordKdf {
        PasswordKdf::mint_with(1024, 1, 1)
    }

    fn vault(store: &MemStore) -> Vault<&MemStore> {
        Vault::create_with(store, "correct horse", cheap()).unwrap()
    }

    #[test]
    fn a_file_put_is_the_file_got_and_the_store_never_sees_it() {
        let store = MemStore::new();
        let v = vault(&store);
        let secret = b"the diary of a very private person".repeat(20);
        v.put("journal/2026/november.md", &secret).unwrap();
        assert_eq!(
            v.get("journal/2026/november.md").unwrap().as_deref(),
            Some(&secret[..])
        );
        assert_eq!(v.get("journal/2026/october.md").unwrap(), None);

        for held in v.held().unwrap() {
            let blob = store.get(&held.name).unwrap().unwrap();
            assert!(!held.name.contains("journal") && !held.name.contains("november"));
            for needle in [&b"diary"[..], b"journal", b"november"] {
                assert!(
                    !blob.windows(needle.len()).any(|w| w == needle),
                    "{} holds {:?}",
                    held.name,
                    String::from_utf8_lossy(needle)
                );
            }
        }
    }

    #[test]
    fn it_opens_with_its_password_and_with_no_other() {
        let store = MemStore::new();
        vault(&store).put("a.txt", b"alpha").unwrap();
        let again = Vault::open(&store, "correct horse").unwrap();
        assert_eq!(again.get("a.txt").unwrap().as_deref(), Some(&b"alpha"[..]));
        assert!(matches!(
            Vault::open(&store, "wrong horse"),
            Err(Error::Open)
        ));
        assert!(matches!(
            Vault::open(&MemStore::new(), "correct horse"),
            Err(Error::Vault(_))
        ));
        assert!(matches!(
            Vault::create_with(&store, "another", cheap()),
            Err(Error::Vault(_))
        ));
    }

    #[test]
    fn a_key_opens_it_without_the_password_until_its_gate_is_removed() {
        let store = MemStore::new();
        let mut v = vault(&store);
        v.put("a.txt", b"alpha").unwrap();
        let key = v.add_key("recovery").unwrap();
        assert!(v.add_key("recovery").is_err());
        assert_eq!(
            v.gates(),
            vec![
                Gate {
                    id: "password".into(),
                    kind: GateType::Password
                },
                Gate {
                    id: "recovery".into(),
                    kind: GateType::Key
                },
            ]
        );

        let by_key = Vault::open_with_key(&store, &format!("  {key}\n")).unwrap();
        assert_eq!(by_key.get("a.txt").unwrap().as_deref(), Some(&b"alpha"[..]));
        let stranger = GateSecret::mint().token();
        assert!(matches!(
            Vault::open_with_key(&store, &stranger),
            Err(Error::Open)
        ));

        v.remove_gate("recovery").unwrap();
        assert!(Vault::open_with_key(&store, &key).is_err());
        assert!(v.remove_gate("password").is_err(), "the last gate stays");
    }

    #[test]
    fn a_new_password_replaces_the_old_and_seals_nothing_again() {
        let store = MemStore::new();
        let mut v = vault(&store);
        v.put("a.txt", b"alpha").unwrap();
        let before: Vec<_> = v
            .held()
            .unwrap()
            .into_iter()
            .filter(|h| h.name != HEADER)
            .map(|h| (h.name.clone(), store.get(&h.name).unwrap()))
            .collect();
        v.set_password_with("battery staple", cheap()).unwrap();
        assert!(Vault::open(&store, "correct horse").is_err());
        let again = Vault::open(&store, "battery staple").unwrap();
        assert_eq!(again.get("a.txt").unwrap().as_deref(), Some(&b"alpha"[..]));
        for (name, blob) in before {
            assert_eq!(store.get(&name).unwrap(), blob);
        }
    }

    #[test]
    fn a_wrap_from_one_vault_opens_nothing_in_another() {
        let (a, b) = (MemStore::new(), MemStore::new());
        let _ = Vault::create_with(&a, "correct horse", cheap()).unwrap();
        let _ = Vault::create_with(&b, "correct horse", cheap()).unwrap();
        // b's header with a's gates: the same password, another vault's wrap.
        let mut ha: Header = serde_json::from_slice(&a.get(HEADER).unwrap().unwrap()).unwrap();
        let hb: Header = serde_json::from_slice(&b.get(HEADER).unwrap().unwrap()).unwrap();
        ha.id = hb.id;
        b.put(HEADER, &serde_json::to_vec(&ha).unwrap()).unwrap();
        assert!(matches!(Vault::open(&b, "correct horse"), Err(Error::Open)));
    }

    #[test]
    fn a_listing_is_every_path_in_order() {
        let store = MemStore::new();
        let v = vault(&store);
        v.put("b.txt", b"bravo").unwrap();
        v.put("a/deep/file.txt", b"alpha!").unwrap();
        v.put("c.txt", b"").unwrap();
        let list = v.list().unwrap();
        assert_eq!(
            list.iter()
                .map(|e| (e.path.as_str(), e.len))
                .collect::<Vec<_>>(),
            vec![("a/deep/file.txt", 6), ("b.txt", 5), ("c.txt", 0)]
        );
        assert_eq!(list[1].digest, sha256_hex(b"bravo"));
        assert_eq!(v.get("c.txt").unwrap().as_deref(), Some(&b""[..]));
    }

    fn count(store: &MemStore, dir: &str) -> usize {
        store.list(dir).unwrap().len()
    }

    #[test]
    fn two_paths_with_the_same_bytes_are_one_object() {
        let store = MemStore::new();
        let v = vault(&store);
        v.put("one.txt", b"same").unwrap();
        v.put("two.txt", b"same").unwrap();
        assert_eq!((count(&store, "e"), count(&store, "c")), (2, 1));
        assert!(v.remove("one.txt").unwrap());
        assert_eq!((count(&store, "e"), count(&store, "c")), (1, 1));
        assert_eq!(v.get("two.txt").unwrap().as_deref(), Some(&b"same"[..]));
        assert!(v.remove("two.txt").unwrap());
        assert!(!v.remove("two.txt").unwrap());
        assert_eq!((count(&store, "e"), count(&store, "c")), (0, 0));
    }

    #[test]
    fn a_file_put_again_replaces_its_bytes_and_leaves_none_behind() {
        let store = MemStore::new();
        let v = vault(&store);
        v.put("a.txt", b"first").unwrap();
        v.put("a.txt", b"second").unwrap();
        assert_eq!(v.get("a.txt").unwrap().as_deref(), Some(&b"second"[..]));
        assert_eq!((count(&store, "e"), count(&store, "c")), (1, 1));
    }

    #[test]
    fn a_file_put_back_as_it_was_is_the_same_blobs() {
        let store = MemStore::new();
        let v = vault(&store);
        v.put("a.txt", b"first").unwrap();
        let snapshot = |v: &Vault<&MemStore>| -> Vec<(String, Vec<u8>)> {
            v.held()
                .unwrap()
                .into_iter()
                .map(|h| (h.name.clone(), store.get(&h.name).unwrap().unwrap()))
                .collect()
        };
        let before = snapshot(&v);
        v.put("a.txt", b"second").unwrap();
        assert_ne!(snapshot(&v), before);
        v.put("a.txt", b"first").unwrap();
        assert_eq!(snapshot(&v), before);
    }

    #[test]
    fn a_rename_moves_the_entry_and_not_the_bytes() {
        let store = MemStore::new();
        let v = vault(&store);
        v.put("old.txt", b"contents").unwrap();
        v.put("in-the-way.txt", b"replaced").unwrap();
        let content = store.list("c").unwrap();
        assert!(v.rename("old.txt", "in-the-way.txt").unwrap());
        assert_eq!(v.get("old.txt").unwrap(), None);
        assert_eq!(
            v.get("in-the-way.txt").unwrap().as_deref(),
            Some(&b"contents"[..])
        );
        assert_eq!((count(&store, "e"), count(&store, "c")), (1, 1));
        assert!(content.contains(&store.list("c").unwrap()[0]));
        assert!(!v.rename("old.txt", "new.txt").unwrap());
        assert!(v.rename("in-the-way.txt", "in-the-way.txt").unwrap());
    }

    #[test]
    fn paths_that_are_not_paths_are_refused() {
        let store = MemStore::new();
        let v = vault(&store);
        for bad in ["", "/a", "a/", "a//b", "../a", "a/./b", "a/..", "a\0b"] {
            assert!(v.put(bad, b"x").is_err(), "{bad:?} was let through");
            assert!(v.get(bad).is_err());
        }
        v.put("spaces and ünïcode/are fine.md", b"x").unwrap();
    }

    #[test]
    fn blobs_swapped_between_names_do_not_open() {
        let store = MemStore::new();
        let v = vault(&store);
        v.put("a.txt", b"alpha").unwrap();
        v.put("b.txt", b"bravo").unwrap();
        let entries = store.list("e").unwrap();
        let (e0, e1) = (format!("e/{}", entries[0].0), format!("e/{}", entries[1].0));
        let (b0, b1) = (
            store.get(&e0).unwrap().unwrap(),
            store.get(&e1).unwrap().unwrap(),
        );
        store.put(&e0, &b1).unwrap();
        store.put(&e1, &b0).unwrap();
        assert!(matches!(v.get("a.txt"), Err(Error::Open)));
        assert!(matches!(v.list(), Err(Error::Open)));
    }

    #[test]
    fn a_tampered_blob_does_not_open() {
        let store = MemStore::new();
        let v = vault(&store);
        v.put("a.txt", b"alpha").unwrap();
        let name = format!("c/{}", store.list("c").unwrap()[0].0);
        let mut blob = store.get(&name).unwrap().unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 1;
        store.put(&name, &blob).unwrap();
        assert!(matches!(v.get("a.txt"), Err(Error::Open)));
        store.delete(&name).unwrap();
        assert!(matches!(v.get("a.txt"), Err(Error::Store(_))));
    }

    #[test]
    fn a_sweep_takes_what_no_entry_names() {
        let store = MemStore::new();
        let v = vault(&store);
        v.put("a.txt", b"alpha").unwrap();
        // A put that stopped after its content and before its entry.
        let (label, key) = v.content_name(&sha256_hex(b"orphan"));
        let frame = seal_derived(&v.root, &v.dek, &label, &key, b"orphan").unwrap();
        store.put(&format!("c/{key}"), &frame).unwrap();
        assert_eq!(count(&store, "c"), 2);
        assert_eq!(v.sweep().unwrap(), 1);
        assert_eq!(v.sweep().unwrap(), 0);
        assert_eq!(v.get("a.txt").unwrap().as_deref(), Some(&b"alpha"[..]));
    }

    #[test]
    fn a_vault_on_disk_opens_again() {
        use crate::store::DirStore;
        let dir =
            std::env::temp_dir().join(format!("agent-sealed-store-vault-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        {
            let v = Vault::create_with(DirStore::new(&dir).unwrap(), "pw", cheap()).unwrap();
            v.put("notes/today.md", b"# Today\n").unwrap();
        }
        let v = Vault::open(DirStore::new(&dir).unwrap(), "pw").unwrap();
        assert_eq!(
            v.get("notes/today.md").unwrap().as_deref(),
            Some(&b"# Today\n"[..])
        );
        assert!(dir.join(HEADER).is_file());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
