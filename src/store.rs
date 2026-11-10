//! Where a vault's bytes are kept: the party that is not trusted with them.
//!
//! A store holds named blobs and nothing else. Every name a vault gives it is
//! `vault.json`, or one directory and 32 hex characters (`e/…`, `c/…`), so a
//! store can be a directory in a synced folder, a bucket, or a map in memory.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::error::{Error, Result};

/// A flat store of named blobs.
///
/// `name` is ASCII: lowercase letters, digits, `.`, `-` and `_`, with at most
/// one `/` in it, as [`check_name`] says. A store need not be atomic across
/// names; a vault never asks it to be.
pub trait Store {
    /// The blob under `name`, or `None` where there is none.
    fn get(&self, name: &str) -> Result<Option<Vec<u8>>>;
    /// Put `bytes` under `name`, replacing what was there, all or nothing.
    fn put(&self, name: &str, bytes: &[u8]) -> Result<()>;
    /// Remove `name`. Removing what is not there is not an error.
    fn delete(&self, name: &str) -> Result<()>;
    /// Every `dir/<leaf>` held, as its leaf and its length in bytes, in name
    /// order. An empty `dir` lists the names with no `/` in them.
    fn list(&self, dir: &str) -> Result<Vec<(String, u64)>>;

    /// The length of the blob under `name`, or `None` where there is none.
    /// A store that can say without fetching the blob should.
    fn size(&self, name: &str) -> Result<Option<u64>> {
        Ok(self.get(name)?.map(|blob| blob.len() as u64))
    }

    /// `len` bytes of the blob under `name` from `offset`, or `None` where
    /// there is no blob. A blob that ends before the range does is an error.
    /// A store that can fetch a range alone should: it is what lets a large
    /// file be read a chunk at a time.
    fn get_range(&self, name: &str, offset: u64, len: usize) -> Result<Option<Vec<u8>>> {
        let Some(blob) = self.get(name)? else {
            return Ok(None);
        };
        usize::try_from(offset)
            .ok()
            .and_then(|start| blob.get(start..)?.get(..len))
            .map(|range| Some(range.to_vec()))
            .ok_or_else(|| Error::Store(format!("{name} ends before the range asked of it")))
    }

    /// Put under `name` what `write` writes, all or nothing: if `write`
    /// fails, nothing is put. A store that can take a blob a piece at a time
    /// should, so a large file is never held whole in memory.
    fn put_with(
        &self,
        name: &str,
        write: &mut dyn FnMut(&mut dyn std::io::Write) -> Result<()>,
    ) -> Result<()> {
        let mut blob = Vec::new();
        write(&mut blob)?;
        self.put(name, &blob)
    }
}

impl<S: Store + ?Sized> Store for &S {
    fn size(&self, name: &str) -> Result<Option<u64>> {
        (**self).size(name)
    }
    fn get_range(&self, name: &str, offset: u64, len: usize) -> Result<Option<Vec<u8>>> {
        (**self).get_range(name, offset, len)
    }
    fn put_with(
        &self,
        name: &str,
        write: &mut dyn FnMut(&mut dyn std::io::Write) -> Result<()>,
    ) -> Result<()> {
        (**self).put_with(name, write)
    }
    fn get(&self, name: &str) -> Result<Option<Vec<u8>>> {
        (**self).get(name)
    }
    fn put(&self, name: &str, bytes: &[u8]) -> Result<()> {
        (**self).put(name, bytes)
    }
    fn delete(&self, name: &str) -> Result<()> {
        (**self).delete(name)
    }
    fn list(&self, dir: &str) -> Result<Vec<(String, u64)>> {
        (**self).list(dir)
    }
}

fn part_ok(part: &str) -> bool {
    !part.is_empty()
        && !part.starts_with('.')
        && part.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'_')
        })
}

/// Whether `name` is one a vault could have given a store. A store that maps
/// names to paths checks this first, so no name climbs out of its directory.
pub fn check_name(name: &str) -> Result<()> {
    let mut parts = name.split('/');
    let ok = match (parts.next(), parts.next(), parts.next()) {
        (Some(a), None, _) => part_ok(a),
        (Some(a), Some(b), None) => part_ok(a) && part_ok(b),
        _ => false,
    };
    if ok {
        Ok(())
    } else {
        Err(Error::Store(format!("not a store name: {name:?}")))
    }
}

fn io(what: &str, path: &Path, e: std::io::Error) -> Error {
    Error::Store(format!("{what} {}: {e}", path.display()))
}

/// A directory on disk: one file per blob, at its name.
///
/// A blob is written beside its place and renamed into it, so a reader never
/// sees half of one and a crash leaves the old blob or the new.
#[derive(Debug, Clone)]
pub struct DirStore {
    root: PathBuf,
}

impl DirStore {
    /// A store over `root`, which is made if it is not there.
    pub fn new(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        std::fs::create_dir_all(&root).map_err(|e| io("creating", &root, e))?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn path(&self, name: &str) -> Result<PathBuf> {
        check_name(name)?;
        Ok(self.root.join(name))
    }
}

impl Store for DirStore {
    fn get(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let path = self.path(name)?;
        match std::fs::read(&path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io("reading", &path, e)),
        }
    }

    fn put(&self, name: &str, bytes: &[u8]) -> Result<()> {
        self.put_with(name, &mut |w| {
            w.write_all(bytes)
                .map_err(|e| Error::Store(format!("writing {name}: {e}")))
        })
    }

    fn put_with(
        &self,
        name: &str,
        write: &mut dyn FnMut(&mut dyn std::io::Write) -> Result<()>,
    ) -> Result<()> {
        let path = self.path(name)?;
        let dir = path.parent().expect("a name under the root");
        std::fs::create_dir_all(dir).map_err(|e| io("creating", dir, e))?;
        // A leading dot keeps the half-written file out of `list`, which
        // admits no name that starts with one.
        let leaf = path.file_name().expect("a name").to_string_lossy();
        let tmp = dir.join(format!(".{leaf}.{}.tmp", std::process::id()));
        let written = (|| {
            let file = std::fs::File::create(&tmp).map_err(|e| io("writing", &path, e))?;
            let mut out = std::io::BufWriter::new(file);
            write(&mut out)?;
            let file = out
                .into_inner()
                .map_err(|e| io("writing", &path, e.into_error()))?;
            file.sync_all().map_err(|e| io("writing", &path, e))?;
            drop(file);
            std::fs::rename(&tmp, &path).map_err(|e| io("writing", &path, e))
        })();
        if written.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        written
    }

    fn size(&self, name: &str) -> Result<Option<u64>> {
        let path = self.path(name)?;
        match std::fs::metadata(&path) {
            Ok(meta) => Ok(Some(meta.len())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io("reading", &path, e)),
        }
    }

    fn get_range(&self, name: &str, offset: u64, len: usize) -> Result<Option<Vec<u8>>> {
        use std::io::{Read, Seek, SeekFrom};
        let path = self.path(name)?;
        let mut file = match std::fs::File::open(&path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io("reading", &path, e)),
        };
        let mut buf = vec![0u8; len];
        file.seek(SeekFrom::Start(offset))
            .and_then(|_| file.read_exact(&mut buf))
            .map_err(|e| io("reading", &path, e))?;
        Ok(Some(buf))
    }

    fn delete(&self, name: &str) -> Result<()> {
        let path = self.path(name)?;
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(io("deleting", &path, e)),
        }
    }

    fn list(&self, dir: &str) -> Result<Vec<(String, u64)>> {
        let path = if dir.is_empty() {
            self.root.clone()
        } else {
            if !part_ok(dir) {
                return Err(Error::Store(format!("not a store directory: {dir:?}")));
            }
            self.root.join(dir)
        };
        let read = match std::fs::read_dir(&path) {
            Ok(read) => read,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(io("listing", &path, e)),
        };
        let mut out = Vec::new();
        for entry in read {
            let entry = entry.map_err(|e| io("listing", &path, e))?;
            let meta = entry.metadata().map_err(|e| io("listing", &path, e))?;
            // What a vault did not put there is not listed: another tool's
            // file, a sync conflict's copy, a half-written blob.
            let Ok(leaf) = entry.file_name().into_string() else {
                continue;
            };
            if meta.is_file() && part_ok(&leaf) {
                out.push((leaf, meta.len()));
            }
        }
        out.sort();
        Ok(out)
    }
}

/// A store in memory: for tests, and for a vault that lives as long as its
/// process.
#[derive(Debug, Default)]
pub struct MemStore {
    blobs: Mutex<BTreeMap<String, Vec<u8>>>,
}

impl MemStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn blobs(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Vec<u8>>> {
        self.blobs.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Store for MemStore {
    fn get(&self, name: &str) -> Result<Option<Vec<u8>>> {
        check_name(name)?;
        Ok(self.blobs().get(name).cloned())
    }

    fn put(&self, name: &str, bytes: &[u8]) -> Result<()> {
        check_name(name)?;
        self.blobs().insert(name.to_string(), bytes.to_vec());
        Ok(())
    }

    fn delete(&self, name: &str) -> Result<()> {
        check_name(name)?;
        self.blobs().remove(name);
        Ok(())
    }

    fn size(&self, name: &str) -> Result<Option<u64>> {
        check_name(name)?;
        Ok(self.blobs().get(name).map(|blob| blob.len() as u64))
    }

    fn list(&self, dir: &str) -> Result<Vec<(String, u64)>> {
        let blobs = self.blobs();
        Ok(blobs
            .iter()
            .filter_map(|(name, bytes)| {
                let leaf = match name.split_once('/') {
                    Some((d, leaf)) if d == dir => leaf,
                    None if dir.is_empty() => name.as_str(),
                    _ => return None,
                };
                Some((leaf.to_string(), bytes.len() as u64))
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_that_would_climb_out_are_refused() {
        for bad in [
            "",
            "..",
            "../x",
            "e/../x",
            "/etc/passwd",
            "e/",
            "/e",
            "a/b/c",
            ".hidden",
            "e/.tmp",
            "E/ABC",
            "e\\x",
            "e/x y",
            "e/x\0",
        ] {
            assert!(check_name(bad).is_err(), "{bad:?} was let through");
        }
        for good in ["vault.json", "e/0123456789abcdef", "c/ab-cd_ef.1"] {
            assert!(check_name(good).is_ok(), "{good:?} was refused");
        }
    }

    fn exercise(store: &dyn Store) {
        assert_eq!(store.get("e/aa").unwrap(), None);
        store.put("e/aa", b"one").unwrap();
        store.put("e/bb", b"three").unwrap();
        store.put("c/aa", b"x").unwrap();
        store.put("vault.json", b"{}").unwrap();
        assert_eq!(store.get("e/aa").unwrap().as_deref(), Some(&b"one"[..]));
        store.put("e/aa", b"two!").unwrap();
        assert_eq!(store.get("e/aa").unwrap().as_deref(), Some(&b"two!"[..]));
        assert_eq!(
            store.list("e").unwrap(),
            vec![("aa".to_string(), 4), ("bb".to_string(), 5)]
        );
        assert_eq!(store.list("").unwrap(), vec![("vault.json".to_string(), 2)]);
        assert_eq!(store.list("nothing").unwrap(), vec![]);
        assert_eq!(store.size("e/bb").unwrap(), Some(5));
        assert_eq!(store.size("e/zz").unwrap(), None);
        assert_eq!(
            store.get_range("e/bb", 1, 3).unwrap().as_deref(),
            Some(&b"hre"[..])
        );
        assert_eq!(store.get_range("e/zz", 0, 1).unwrap(), None);
        assert!(store.get_range("e/bb", 3, 3).is_err(), "past its end");
        store
            .put_with("c/bb", &mut |w| {
                w.write_all(b"in two ").unwrap();
                w.write_all(b"pieces").unwrap();
                Ok(())
            })
            .unwrap();
        assert_eq!(
            store.get("c/bb").unwrap().as_deref(),
            Some(&b"in two pieces"[..])
        );
        // A write that fails puts nothing, and leaves what was there.
        let failed = store.put_with("c/bb", &mut |w| {
            w.write_all(b"half").unwrap();
            Err(Error::Seal)
        });
        assert_eq!(failed, Err(Error::Seal));
        assert_eq!(
            store.get("c/bb").unwrap().as_deref(),
            Some(&b"in two pieces"[..])
        );
        store.delete("c/bb").unwrap();
        store.delete("e/aa").unwrap();
        store.delete("e/aa").unwrap();
        assert_eq!(store.get("e/aa").unwrap(), None);
        assert!(store.put("../escape", b"x").is_err());
    }

    #[test]
    fn a_store_in_memory_keeps_what_it_is_given() {
        exercise(&MemStore::new());
    }

    #[test]
    fn a_directory_keeps_what_it_is_given_and_lists_nothing_else() {
        let dir =
            std::env::temp_dir().join(format!("agent-sealed-store-store-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = DirStore::new(&dir).unwrap();
        exercise(&store);
        // Another tool's file beside a vault's is not a vault's blob.
        std::fs::write(dir.join("e").join("bb (conflicted copy)"), b"?").unwrap();
        std::fs::write(dir.join("e").join(".bb.1.tmp"), b"?").unwrap();
        assert_eq!(store.list("e").unwrap(), vec![("bb".to_string(), 5)]);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
