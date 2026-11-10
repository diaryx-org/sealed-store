//! The page: a vault in a directory, opened and worked on by hand.
//!
//! It is for trying sealed-store, not for keeping a diary in. Everything it does is
//! one call on [`sealed_store::Vault`], made on the page's own thread, so a password
//! being stretched holds the window still for as long as Argon2id takes.
//!
//! The binary shows the page in a window; the tests lay it out headless and
//! press it.

use std::path::PathBuf;

use dioxus::prelude::*;
use sealed_store::{DirStore, Entry as File, Gate, GateType, Held, Vault};
use unit::prelude::*;

/// The largest file shown as text in the page.
const PREVIEW_LIMIT: usize = 64 * 1024;

/// The page, at the directory `SEALED_STORE_VAULT` names, or `~/sealed-store-vault`.
#[allow(non_snake_case)]
pub fn App() -> Element {
    let dir =
        std::env::var("SEALED_STORE_VAULT").unwrap_or_else(|_| "~/sealed-store-vault".to_string());
    rsx! { AppAt { dir } }
}

/// The page over the directory `dir`, not yet built: for a host that is not
/// a window, as a test is.
pub fn page_at(dir: impl Into<String>) -> VirtualDom {
    VirtualDom::new_with_props(AppAt, AppAtProps { dir: dir.into() })
}

/// The page with its directory field already reading `dir`.
#[component]
pub fn AppAt(dir: String) -> Element {
    let state = use_hook(|| State {
        vault: Signal::new(None),
        dir: Signal::new(dir),
        files: Signal::new(Vec::new()),
        held: Signal::new(Vec::new()),
        gates: Signal::new(Vec::new()),
        said: Signal::new(Said::plain("No vault is open.")),
        selected: Signal::new(None),
        minted: Signal::new(None),
    });
    let open = state.vault.read().is_some();
    let said = state.said.read().clone();
    rsx! {
        UnitRoot { class: "vault-page",
            style { {CSS} }
            Stack { gap: 16.0,
                Stack { axis: Axis::Horizontal, align: Align::Center, wrap: true,
                    Heading { level: 1, "Sealed store" }
                    Badge { tone: if open { Tone::Success } else { Tone::Neutral },
                        if open { "open" } else { "locked" }
                    }
                    Spacer {}
                    if open {
                        Button { onpress: move |_| state.lock(), "Lock" }
                    }
                }
                div { class: "vault-said {said.class()}", role: "status", "{said.text}" }
                if open {
                    Opened { state }
                } else {
                    Locked { state }
                }
            }
        }
    }
}

/// What the page last did, and whether it went wrong.
#[derive(Clone, PartialEq)]
struct Said {
    wrong: bool,
    text: String,
}

impl Said {
    fn plain(text: impl Into<String>) -> Self {
        Said {
            wrong: false,
            text: text.into(),
        }
    }

    fn class(&self) -> &'static str {
        if self.wrong { "wrong" } else { "" }
    }
}

/// The page's state: the open vault, and what was last read out of it.
#[derive(Clone, Copy, PartialEq)]
struct State {
    vault: Signal<Option<Vault<DirStore>>>,
    dir: Signal<String>,
    files: Signal<Vec<File>>,
    held: Signal<Vec<Held>>,
    gates: Signal<Vec<Gate>>,
    said: Signal<Said>,
    selected: Signal<Option<String>>,
    /// A key just made, shown once: (the gate's id, the key).
    minted: Signal<Option<(String, String)>>,
}

/// `~/…` under the home directory, and anything else as it is.
fn on_disk(path: &str) -> PathBuf {
    let path = path.trim();
    match (path.strip_prefix("~/"), std::env::var_os("HOME")) {
        (Some(rest), Some(home)) => PathBuf::from(home).join(rest),
        _ => PathBuf::from(path),
    }
}

fn size(len: u64) -> String {
    match len {
        0..=1023 => format!("{len} B"),
        1024..=1_048_575 => format!("{:.1} KiB", len as f64 / 1024.0),
        _ => format!("{:.1} MiB", len as f64 / 1_048_576.0),
    }
}

impl State {
    fn say(mut self, text: impl Into<String>) {
        self.said.set(Said::plain(text));
    }

    fn fail(mut self, what: &str, e: impl std::fmt::Display) {
        self.said.set(Said {
            wrong: true,
            text: format!("{what}: {e}"),
        });
    }

    /// Read the vault again: its files, its gates, and what its store holds.
    fn refresh(mut self) {
        let vault = self.vault.peek();
        let Some(v) = vault.as_ref() else {
            return;
        };
        match (v.list(), v.held()) {
            (Ok(files), Ok(held)) => {
                let gone = self
                    .selected
                    .peek()
                    .as_ref()
                    .is_some_and(|path| !files.iter().any(|f| f.path == *path));
                if gone {
                    self.selected.set(None);
                }
                self.files.set(files);
                self.held.set(held);
                self.gates.set(v.gates());
            }
            (Err(e), _) | (_, Err(e)) => self.fail("Reading the vault", e),
        }
    }

    /// Run `f` on the open vault, say `done` or what went wrong, and read
    /// the vault again.
    fn with(self, what: &str, f: impl FnOnce(&Vault<DirStore>) -> sealed_store::Result<String>) {
        let outcome = {
            let vault = self.vault.peek();
            let Some(v) = vault.as_ref() else {
                return;
            };
            f(v)
        };
        match outcome {
            Ok(done) => self.say(done),
            Err(e) => self.fail(what, e),
        }
        self.refresh();
    }

    fn opened(mut self, vault: Vault<DirStore>, how: &str) {
        self.vault.set(Some(vault));
        self.say(how);
        self.refresh();
    }

    fn store(self) -> sealed_store::Result<DirStore> {
        DirStore::new(on_disk(&self.dir.peek()))
    }

    fn create(self, password: &str) {
        if password.is_empty() {
            return self.fail("Making a vault", "it needs a password");
        }
        match self.store().and_then(|s| Vault::create(s, password)) {
            Ok(v) => self.opened(v, "Made a new vault and opened it."),
            Err(e) => self.fail("Making a vault", e),
        }
    }

    fn open(self, password: &str) {
        match self.store().and_then(|s| Vault::open(s, password)) {
            Ok(v) => self.opened(v, "Opened with the password."),
            Err(e) => self.fail("Opening the vault", e),
        }
    }

    fn open_with_key(self, key: &str) {
        match self.store().and_then(|s| Vault::open_with_key(s, key)) {
            Ok(v) => self.opened(v, "Opened with a key."),
            Err(e) => self.fail("Opening the vault", e),
        }
    }

    fn lock(mut self) {
        self.vault.set(None);
        self.files.set(Vec::new());
        self.held.set(Vec::new());
        self.gates.set(Vec::new());
        self.selected.set(None);
        self.minted.set(None);
        self.say("Locked. The keys are gone from this window.");
    }

    fn add_key(mut self, id: &str) {
        let outcome = {
            let mut vault = self.vault.write();
            let Some(v) = vault.as_mut() else {
                return;
            };
            v.add_key(id)
        };
        match outcome {
            Ok(key) => {
                self.minted.set(Some((id.to_string(), key)));
                self.say(format!("Added the key {id:?}."));
            }
            Err(e) => self.fail("Adding a key", e),
        }
        self.refresh();
    }

    fn remove_gate(mut self, id: &str) {
        let outcome = {
            let mut vault = self.vault.write();
            let Some(v) = vault.as_mut() else {
                return;
            };
            v.remove_gate(id)
        };
        match outcome {
            Ok(()) => {
                if self.minted.peek().as_ref().is_some_and(|(of, _)| of == id) {
                    self.minted.set(None);
                }
                self.say(format!("Removed the gate {id:?}."));
            }
            Err(e) => self.fail("Removing a gate", e),
        }
        self.refresh();
    }
}

const CSS: &str = r#"
html, body { margin: 0; }
.vault-page { min-height: 100vh; padding: 20px 24px 60px; }
.vault-said { color: var(--unit-dim); }
.vault-said.wrong { color: var(--unit-danger); }
.vault-grid { display: flex; flex-wrap: wrap; gap: 16px; align-items: flex-start; }
.vault-grid > .unit-card { width: 380px; max-width: 100%; }
.vault-grid > .unit-card.wide { width: 776px; }
.vault-mono { font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; font-size: 0.85em;
             white-space: pre-wrap; overflow-wrap: anywhere; margin: 0; }
.vault-preview { max-height: 260px; overflow: auto; padding: 8px 10px;
                border: 1px solid var(--unit-border); border-radius: 6px; }
.vault-held { display: flex; gap: 12px; justify-content: space-between; }
.vault-held .len { color: var(--unit-dim); flex: none; }
"#;

/// No vault open: a directory, and a password or a key to open it with.
#[component]
fn Locked(state: State) -> Element {
    let mut dir = state.dir;
    let mut password = use_signal(String::new);
    let mut key = use_signal(String::new);
    rsx! {
        div { class: "vault-grid",
            Card { title: "A vault in a directory",
                Stack {
                    TextField { label: "Directory", name: "dir", value: dir(),
                                placeholder: "~/sealed-store-vault", oninput: move |v| dir.set(v) }
                    TextField { label: "Password", name: "password", kind: InputKind::Password,
                                value: password(), oninput: move |v| password.set(v),
                                onsubmit: move |v: String| state.open(&v) }
                    Stack { axis: Axis::Horizontal, wrap: true,
                        Button { variant: Variant::Primary,
                                 onpress: move |_| state.open(&password.peek()), "Open" }
                        Button { onpress: move |_| state.create(&password.peek()),
                                 "Make a new vault here" }
                    }
                    Text { dim: true,
                        "The directory holds the vault's sealed files and nothing else. "
                        "Put it anywhere, a synced folder included."
                    }
                }
            }
            Card { title: "Or a key",
                Stack {
                    TextField { label: "Key", name: "key", value: key(),
                                placeholder: "43 characters", oninput: move |v| key.set(v),
                                action: "Open", onaction: move |v: String| state.open_with_key(&v) }
                    Text { dim: true,
                        "A key an open vault made: a recovery key, or one for this device."
                    }
                }
            }
        }
    }
}

/// A vault open: its files, one of them, its gates, and what its keeper sees.
#[component]
fn Opened(state: State) -> Element {
    let files = state.files.read().clone();
    let selected = state.selected.read().clone();
    let chosen = selected
        .as_ref()
        .and_then(|path| files.iter().find(|f| f.path == *path).cloned());
    let mut selected_signal = state.selected;
    rsx! {
        div { class: "vault-grid",
            Card { title: "Files",
                if files.is_empty() {
                    Text { dim: true, "Nothing is kept here yet." }
                } else {
                    Section {
                        for file in files.iter().cloned() {
                            Row { key: "{file.path}", title: file.path.clone(), detail: size(file.len),
                                  accessory: Accessory::Check(selected.as_deref() == Some(file.path.as_str())),
                                  onpress: move |_| selected_signal.set(Some(file.path.clone())) }
                        }
                    }
                }
            }
            if let Some(file) = chosen {
                OneFile { state, file }
            }
            Write { state }
            BringIn { state }
            Gates { state }
            Keeper { state }
        }
    }
}

/// A note typed into the page and kept at a path.
#[component]
fn Write(state: State) -> Element {
    let mut path = use_signal(String::new);
    let mut text = use_signal(String::new);
    let mut selected = state.selected;
    rsx! {
        Card { title: "Write a note",
            Stack {
                TextField { label: "Path in the vault", name: "note-path", value: path(),
                            placeholder: "journal/today.md", oninput: move |v| path.set(v) }
                TextArea { label: "Text", name: "note-text", value: text(), rows: 5,
                           oninput: move |v| text.set(v) }
                Button { variant: Variant::Primary, onpress: move |_| {
                    let at = path.peek().trim().to_string();
                    let body = text.peek().clone();
                    state.with("Keeping the note", |v| {
                        v.put(&at, body.as_bytes())?;
                        Ok(format!("Kept {at:?}: {}.", size(body.len() as u64)))
                    });
                    if !state.said.peek().wrong {
                        selected.set(Some(at));
                        path.set(String::new());
                        text.set(String::new());
                    }
                }, "Keep" }
            }
        }
    }
}

/// A file read off the disk and kept at a path.
#[component]
fn BringIn(state: State) -> Element {
    let mut from = use_signal(String::new);
    let mut path = use_signal(String::new);
    let mut selected = state.selected;
    rsx! {
        Card { title: "Bring in a file",
            Stack {
                TextField { label: "File on disk", name: "from", value: from(),
                            placeholder: "~/Documents/letter.pdf", oninput: move |v| from.set(v) }
                TextField { label: "Path in the vault", name: "as", value: path(),
                            placeholder: "the file's own name", oninput: move |v| path.set(v) }
                Button { onpress: move |_| {
                    let source = on_disk(&from.peek());
                    let at = match path.peek().trim() {
                        "" => source.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
                        given => given.to_string(),
                    };
                    // Read off the disk a piece at a time: a film is not held in memory.
                    state.with("Keeping the file", |v| {
                        let len = v.put_file(&at, &source)?;
                        Ok(format!("Kept {at:?}: {}.", size(len)))
                    });
                    if !state.said.peek().wrong {
                        selected.set(Some(at));
                        from.set(String::new());
                        path.set(String::new());
                    }
                }, "Keep a copy in the vault" }
            }
        }
    }
}

/// The selected file: its bytes if they are text, and what can be done to it.
#[component]
fn OneFile(state: State, file: File) -> Element {
    let mut rename_to = use_signal(String::new);
    let mut copy_to = use_signal(String::new);
    let mut selected = state.selected;
    let path = file.path.clone();

    // Opened again whenever the entry is another: the digest changes with
    // the bytes.
    // Only the head of the file is opened: of a chunked one, its first chunk.
    let shown = {
        let vault = state.vault.read();
        let mut head = vec![0u8; PREVIEW_LIMIT.min(file.len as usize)];
        match vault.as_ref().map(|v| v.read_at(&file.path, 0, &mut head)) {
            Some(Ok(Some(_))) if file.len as usize > PREVIEW_LIMIT => {
                Err(format!("{} is more than this page shows.", size(file.len)))
            }
            Some(Ok(Some(n))) => {
                head.truncate(n);
                String::from_utf8(head).map_err(|_| "These bytes are not text.".to_string())
            }
            Some(Ok(None)) | None => Err("It is gone.".to_string()),
            Some(Err(e)) => Err(format!("It does not open: {e}")),
        }
    };

    rsx! {
        Card { title: file.path.clone(),
            Stack {
                Text { dim: true, "{size(file.len)}, SHA-256 " span { class: "vault-mono", "{file.digest}" } }
                match shown {
                    Ok(text) => rsx! { pre { class: "vault-mono vault-preview", "{text}" } },
                    Err(why) => rsx! { Text { dim: true, "{why}" } },
                }
                Divider {}
                TextField { label: "Move to", name: "rename", value: rename_to(),
                            placeholder: path.clone(), oninput: move |v| rename_to.set(v),
                            action: "Move", action_disabled: rename_to().trim().is_empty(),
                            onaction: {
                                let path = path.clone();
                                move |to: String| {
                                    let to = to.trim().to_string();
                                    state.with("Moving the file", |v| {
                                        v.rename(&path, &to)?;
                                        Ok(format!("Moved {path:?} to {to:?}. Its bytes were not sealed again."))
                                    });
                                    if !state.said.peek().wrong {
                                        selected.set(Some(to));
                                        rename_to.set(String::new());
                                    }
                                }
                            } }
                TextField { label: "Save a copy on disk at", name: "copy-to", value: copy_to(),
                            placeholder: "~/Desktop/copy.md", oninput: move |v| copy_to.set(v),
                            action: "Save", action_disabled: copy_to().trim().is_empty(),
                            onaction: {
                                let path = path.clone();
                                move |to: String| {
                                    let to = on_disk(&to);
                                    state.with("Saving a copy", |v| {
                                        let write = |e: std::io::Error| {
                                            sealed_store::Error::Io(format!("writing {}: {e}", to.display()))
                                        };
                                        let mut out = std::fs::File::create(&to).map_err(write)?;
                                        // Written a chunk at a time; a file that does not
                                        // open whole is not left half-written.
                                        match v.get_to(&path, &mut out) {
                                            Ok(Some(_)) => {}
                                            Ok(None) => {
                                                let _ = std::fs::remove_file(&to);
                                                return Err(sealed_store::Error::Vault(format!("{path:?} is gone")));
                                            }
                                            Err(e) => {
                                                let _ = std::fs::remove_file(&to);
                                                return Err(e);
                                            }
                                        }
                                        Ok(format!("Saved {path:?} in the clear at {}.", to.display()))
                                    });
                                    if !state.said.peek().wrong {
                                        copy_to.set(String::new());
                                    }
                                }
                            } }
                Button { variant: Variant::Danger, onpress: {
                    let path = path.clone();
                    move |_| state.with("Removing the file", |v| {
                        v.remove(&path)?;
                        Ok(format!("Removed {path:?}."))
                    })
                }, "Remove from the vault" }
            }
        }
    }
}

/// The ways in, and a key made to be another.
#[component]
fn Gates(state: State) -> Element {
    let gates = state.gates.read().clone();
    let minted = state.minted.read().clone();
    let mut id = use_signal(String::new);
    let mut minted_signal = state.minted;
    rsx! {
        Card { title: "Ways in",
            Stack {
                Section {
                    {gates.iter().map(|gate| {
                        let kind = match gate.kind {
                            GateType::Password => "password",
                            GateType::Key => "key",
                        };
                        // A key's gate can go; the password's is replaced, not removed.
                        let id = gate.id.clone();
                        let remove = (gate.kind == GateType::Key).then(|| rsx! {
                            Button { variant: Variant::Ghost, label: format!("Remove {id}"),
                                     onpress: move |_| state.remove_gate(&id), "Remove" }
                        });
                        rsx! {
                            Row { key: "{gate.id}", title: gate.id.clone(), detail: kind.to_string(),
                                  trailing: remove }
                        }
                    })}
                }
                TextField { label: "A new key, named", name: "gate-id", value: id(),
                            placeholder: "recovery", oninput: move |v| id.set(v),
                            action: "Add", action_disabled: id().trim().is_empty(),
                            onaction: move |named: String| {
                                state.add_key(named.trim());
                                if !state.said.peek().wrong {
                                    id.set(String::new());
                                }
                            } }
                if let Some((of, key)) = minted {
                    Callout { tone: Tone::Warning, title: format!("The key {of:?}, shown once"),
                              ondismiss: move |_| minted_signal.set(None),
                        pre { class: "vault-mono vault-key", "{key}" }
                        "It opens the vault with no password, and is kept nowhere but here."
                    }
                }
                Text { dim: true,
                    "Removing a key closes its gate and does not change the lock: "
                    "whoever opened the vault with it may have kept what it gave them."
                }
            }
        }
    }
}

/// What the directory's keeper sees: names and lengths.
#[component]
fn Keeper(state: State) -> Element {
    let held = state.held.read().clone();
    let total: u64 = held.iter().map(|h| h.len).sum();
    let dir = on_disk(&state.dir.read());
    rsx! {
        Card { title: "What the directory's keeper sees", class: "wide",
            Stack {
                Text { dim: true, "{dir.display()}: {held.len()} blobs, {size(total)}." }
                div { class: "vault-mono vault-keeper",
                    for blob in held {
                        div { key: "{blob.name}", class: "vault-held",
                            span { class: "name", "{blob.name}" }
                            span { class: "len", "{blob.len} B" }
                        }
                    }
                }
                Stack { axis: Axis::Horizontal, align: Align::Center, wrap: true,
                    Button { onpress: move |_| { state.refresh(); state.say("Read the directory again."); },
                             "Read again" }
                    Button { onpress: move |_| state.with("Sweeping", |v| {
                        Ok(match v.sweep()? {
                            0 => "Nothing to sweep: every blob is some file's.".to_string(),
                            n => format!("Swept {n} blobs no file names."),
                        })
                    }), "Sweep" }
                }
                Text { dim: true,
                    "e/ is one entry per file, c/ a file's bytes, chunked past 1 MiB. The names are HMACs, the lengths "
                    "padded, and vault.json holds the gates: a salt, and the root wrapped once per gate."
                }
            }
        }
    }
}
