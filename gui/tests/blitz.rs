//! The page laid out by Blitz with no window, and pressed and typed at as a
//! window's events would: a vault made, written to, locked, and opened again
//! by its password and by a key, with the directory read after each.
//!
//! The harness is unit-gallery's (`gallery/tests/blitz.rs` there).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::task::{Context, Waker};

use atomic_refcell::AtomicRefCell;
use blitz_dom::{Document, DocumentConfig};
use blitz_traits::events::{
    BlitzKeyEvent, BlitzPointerEvent, BlitzPointerId, KeyState, MouseEventButton,
    MouseEventButtons, PointerCoords, PointerDetails, UiEvent,
};
use blitz_traits::node_id::NodeId;
use blitz_traits::shell::{ColorScheme, Viewport};
use dioxus::prelude::*;
use dioxus_native::DioxusDocument;
use keyboard_types::{Code, Key, Location, Modifiers};

/// A directory for one test's vault, removed when the test is over.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "agent-sealed-store-gui-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The page over the vault directory `dir`, built and laid out.
fn page(dir: &Path) -> DioxusDocument {
    let vdom = sealed_store_gui::page_at(dir.to_string_lossy());
    let mut doc = DioxusDocument::new(vdom, DocumentConfig::default());
    doc.inner
        .borrow_mut()
        .set_viewport(Viewport::new(1280, 2400, 1.0, ColorScheme::Light));
    doc.initial_build();
    settle(&mut doc);
    doc
}

/// Poll the page and lay it out, as a window's turn and its next frame do.
fn settle(doc: &mut DioxusDocument) {
    for _ in 0..3 {
        Document::poll(doc, Some(Context::from_waker(Waker::noop())));
        doc.inner.borrow_mut().resolve(0.0);
    }
}

fn one(doc: &DioxusDocument, selector: &str) -> NodeId {
    doc.inner
        .borrow()
        .query_selector(selector)
        .unwrap()
        .unwrap_or_else(|| panic!("no {selector}"))
}

/// The text of every element matching `selector`.
fn texts(doc: &DioxusDocument, selector: &str) -> Vec<String> {
    let inner = doc.inner.borrow();
    inner
        .query_selector_all(selector)
        .unwrap()
        .iter()
        .map(|&id| {
            inner
                .get_node(id)
                .unwrap()
                .text_content()
                .trim()
                .to_string()
        })
        .collect()
}

/// The first element matching `selector` whose text is `text`.
fn find(doc: &DioxusDocument, selector: &str, text: &str) -> NodeId {
    let inner = doc.inner.borrow();
    let all = inner.query_selector_all(selector).unwrap();
    *all.iter()
        .find(|&&id| inner.get_node(id).unwrap().text_content().trim() == text)
        .unwrap_or_else(|| panic!("no {selector} reading {text:?}"))
}

fn pointer(x: f64, y: f64, buttons: MouseEventButtons) -> BlitzPointerEvent {
    let (x, y) = (x as f32, y as f32);
    BlitzPointerEvent {
        id: BlitzPointerId::Mouse,
        is_primary: true,
        coords: PointerCoords {
            page_x: x,
            page_y: y,
            screen_x: x,
            screen_y: y,
            client_x: x,
            client_y: y,
        },
        button: MouseEventButton::Main,
        buttons,
        mods: Modifiers::empty(),
        details: PointerDetails::default(),
        element: Default::default(),
        active_pointers: Arc::new(AtomicRefCell::new(Vec::new())),
    }
}

/// A press and release at the middle of `node`.
fn click(doc: &mut DioxusDocument, node: NodeId) {
    let r = doc.inner.borrow().get_client_bounding_rect(node).unwrap();
    let (x, y) = (r.x + r.width / 2.0, r.y + r.height / 2.0);
    assert!(
        r.width > 0.0 && r.height > 0.0,
        "pressed something not drawn"
    );
    doc.handle_ui_event(UiEvent::PointerMove(pointer(x, y, MouseEventButtons::None)));
    doc.handle_ui_event(UiEvent::PointerDown(pointer(
        x,
        y,
        MouseEventButtons::Primary,
    )));
    settle(doc);
    doc.handle_ui_event(UiEvent::PointerUp(pointer(x, y, MouseEventButtons::None)));
    settle(doc);
}

/// `text` typed into the field matching `selector`.
fn type_into(doc: &mut DioxusDocument, selector: &str, text: &str) {
    let field = one(doc, selector);
    click(doc, field);
    for c in text.chars() {
        let event = |state| BlitzKeyEvent {
            key: Key::Character(c.to_string()),
            code: Code::Unidentified,
            modifiers: Modifiers::empty(),
            location: Location::Standard,
            is_auto_repeating: false,
            is_composing: false,
            state,
            text: Some(c.to_string().into()),
        };
        doc.handle_ui_event(UiEvent::KeyDown(event(KeyState::Pressed)));
        doc.handle_ui_event(UiEvent::KeyUp(event(KeyState::Released)));
        settle(doc);
    }
}

fn press(doc: &mut DioxusDocument, button: &str) {
    let node = find(doc, "button", button);
    click(doc, node);
}

/// What the page says it last did, and whether it says it went wrong.
fn said(doc: &DioxusDocument) -> (String, bool) {
    let node = one(doc, ".vault-said");
    let inner = doc.inner.borrow();
    let node = inner.get_node(node).unwrap();
    let wrong = node
        .attr(blitz_dom::local_name!("class"))
        .unwrap_or("")
        .contains("wrong");
    (node.text_content().trim().to_string(), wrong)
}

fn badge(doc: &DioxusDocument) -> String {
    texts(doc, ".unit-badge").remove(0)
}

/// Every file under `dir`, with its bytes.
fn on_disk(dir: &Path) -> Vec<(String, Vec<u8>)> {
    fn walk(dir: &Path, under: &Path, out: &mut Vec<(String, Vec<u8>)>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, under, out);
            } else {
                let name = path
                    .strip_prefix(under)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                out.push((name, std::fs::read(&path).unwrap()));
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.sort();
    out
}

const NOTE: &str = "Dear diary, nobody may read this";

/// A vault made in the page, with one note kept in it.
fn with_a_note(scratch: &Scratch) -> DioxusDocument {
    let mut doc = page(&scratch.0);
    assert_eq!(badge(&doc), "locked");
    type_into(&mut doc, "input[name='password']", "correct horse");
    press(&mut doc, "Make a new vault here");
    assert_eq!(
        said(&doc),
        ("Made a new vault and opened it.".into(), false)
    );
    assert_eq!(badge(&doc), "open");

    type_into(&mut doc, "input[name='note-path']", "journal/today.md");
    type_into(&mut doc, "textarea[name='note-text']", NOTE);
    press(&mut doc, "Keep");
    assert_eq!(
        said(&doc),
        ("Kept \"journal/today.md\": 32 B.".into(), false)
    );
    doc
}

#[test]
fn a_note_kept_in_the_page_is_sealed_in_the_directory() {
    let scratch = Scratch::new("note");
    let doc = with_a_note(&scratch);

    // In the page: the file, chosen, and its text read back out of the vault.
    assert_eq!(texts(&doc, ".unit-row-title")[0], "journal/today.md");
    assert_eq!(texts(&doc, ".vault-preview"), vec![NOTE.to_string()]);

    // In the keeper's list, and in the directory itself: a header, an entry
    // and the bytes, under names and in bytes that say nothing.
    let names = texts(&doc, ".vault-held .name");
    assert_eq!(names.len(), 3, "{names:?}");
    assert_eq!(names[0], "vault.json");
    assert!(
        names[1].starts_with("e/") && names[2].starts_with("c/"),
        "{names:?}"
    );

    let files = on_disk(&scratch.0);
    assert_eq!(
        files.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(),
        {
            let mut sorted: Vec<&str> = names.iter().map(String::as_str).collect();
            sorted.sort();
            sorted
        },
        "the page lists what the directory holds"
    );
    for (name, bytes) in &files {
        for needle in ["diary", "journal", "today", "correct horse"] {
            assert!(!name.contains(needle), "{name} is named in the clear");
            assert!(
                !bytes.windows(needle.len()).any(|w| w == needle.as_bytes()),
                "{name} holds {needle:?} in the clear"
            );
        }
    }
}

#[test]
fn a_locked_vault_opens_with_its_password_and_no_other() {
    let scratch = Scratch::new("lock");
    let mut doc = with_a_note(&scratch);
    press(&mut doc, "Lock");
    assert_eq!(badge(&doc), "locked");
    assert!(
        texts(&doc, ".unit-row-title").is_empty(),
        "a locked page lists nothing"
    );
    assert!(texts(&doc, ".vault-preview").is_empty());

    type_into(&mut doc, "input[name='password']", "wrong horse");
    press(&mut doc, "Open");
    let (text, wrong) = said(&doc);
    assert!(
        wrong && text.starts_with("Opening the vault: open failed"),
        "{text}"
    );
    assert_eq!(badge(&doc), "locked");

    // A window opened afresh on the same directory, as the next launch is.
    let mut doc = page(&scratch.0);
    type_into(&mut doc, "input[name='password']", "correct horse");
    press(&mut doc, "Open");
    assert_eq!(said(&doc), ("Opened with the password.".into(), false));
    assert_eq!(texts(&doc, ".unit-row-title")[0], "journal/today.md");
    let row = find(&doc, ".unit-row-title", "journal/today.md");
    click(&mut doc, row);
    assert_eq!(texts(&doc, ".vault-preview"), vec![NOTE.to_string()]);
}

#[test]
fn a_key_made_in_the_page_opens_the_vault_without_the_password() {
    let scratch = Scratch::new("key");
    let mut doc = with_a_note(&scratch);
    type_into(&mut doc, "input[name='gate-id']", "recovery");
    let add = find(&doc, ".unit-field-action button", "Add");
    click(&mut doc, add);
    assert_eq!(said(&doc), ("Added the key \"recovery\".".into(), false));
    let key = texts(&doc, ".vault-key").remove(0);
    assert_eq!(key.len(), 43, "32 bytes, base64url: {key}");

    press(&mut doc, "Lock");
    assert!(
        texts(&doc, ".vault-key").is_empty(),
        "the key went with the lock"
    );
    type_into(&mut doc, "input[name='key']", &key);
    let open = find(&doc, ".unit-field-action button", "Open");
    click(&mut doc, open);
    assert_eq!(said(&doc), ("Opened with a key.".into(), false));
    assert_eq!(texts(&doc, ".unit-row-title")[0], "journal/today.md");
}

#[test]
fn a_file_moved_and_removed_leaves_the_directory_as_it_should_be() {
    let scratch = Scratch::new("move");
    let mut doc = with_a_note(&scratch);
    let content = |dir: &Path| -> Vec<(String, Vec<u8>)> {
        on_disk(dir)
            .into_iter()
            .filter(|(n, _)| n.starts_with("c/"))
            .collect()
    };
    let before = content(&scratch.0);

    type_into(&mut doc, "input[name='rename']", "archive/kept.md");
    let go = find(&doc, ".unit-field-action button", "Move");
    click(&mut doc, go);
    let (text, wrong) = said(&doc);
    assert!(
        !wrong && text.starts_with("Moved \"journal/today.md\" to \"archive/kept.md\""),
        "{text}"
    );
    assert_eq!(texts(&doc, ".unit-row-title")[0], "archive/kept.md");
    assert_eq!(texts(&doc, ".vault-preview"), vec![NOTE.to_string()]);
    assert_eq!(
        content(&scratch.0),
        before,
        "the bytes were not sealed again"
    );

    press(&mut doc, "Remove from the vault");
    assert_eq!(said(&doc), ("Removed \"archive/kept.md\".".into(), false));
    assert_eq!(
        texts(&doc, ".vault-held .name"),
        vec!["vault.json".to_string()]
    );
    assert_eq!(on_disk(&scratch.0).len(), 1, "only the header is left");
}

#[test]
fn a_large_file_is_brought_in_chunked_and_saved_back_whole() {
    let scratch = Scratch::new("large");
    let outside = Scratch::new("large-outside");
    std::fs::create_dir_all(&outside.0).unwrap();
    // Three mebibytes that do not compress, with the note's words in them.
    let mut film: Vec<u8> = (0..3 * 1024 * 1024u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect();
    film[2_000_000..2_000_032].copy_from_slice(NOTE.as_bytes());
    let source = outside.0.join("film.mov");
    std::fs::write(&source, &film).unwrap();

    let mut doc = with_a_note(&scratch);
    type_into(&mut doc, "input[name='from']", &source.to_string_lossy());
    press(&mut doc, "Keep a copy in the vault");
    assert_eq!(said(&doc), ("Kept \"film.mov\": 3.0 MiB.".into(), false));
    assert_eq!(
        texts(&doc, ".unit-row-title")[..2],
        ["film.mov", "journal/today.md"]
    );

    // In the directory: a chunked frame, a little longer than the film, with
    // none of the film's words in it.
    let sealed = on_disk(&scratch.0)
        .into_iter()
        .find(|(name, bytes)| name.starts_with("c/") && bytes.len() > 1 << 20)
        .expect("the film's bytes");
    assert_eq!(&sealed.1[..4], b"DEP2");
    assert!(sealed.1.len() > film.len() && sealed.1.len() < film.len() * 9 / 8);
    assert!(!sealed.1.windows(NOTE.len()).any(|w| w == NOTE.as_bytes()));

    let copy = outside.0.join("copy.mov");
    type_into(&mut doc, "input[name='copy-to']", &copy.to_string_lossy());
    let save = find(&doc, ".unit-field-action button", "Save");
    click(&mut doc, save);
    let (text, wrong) = said(&doc);
    assert!(
        !wrong && text.starts_with("Saved \"film.mov\" in the clear"),
        "{text}"
    );
    assert_eq!(std::fs::read(&copy).unwrap(), film);
}
