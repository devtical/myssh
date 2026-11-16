use crate::error::{MySshError, Result};
use crate::keys::{format_key_detail, list_ssh_keys, SshKeyInfo};
use cursive::align::HAlign;
use cursive::traits::*;
use cursive::views::{Dialog, SelectView, TextView};
use cursive::Cursive;
use std::path::{Path, PathBuf};
use std::sync::Arc;

struct AppState {
    ssh_dir: PathBuf,
    keys: Vec<SshKeyInfo>,
}

pub fn run(ssh_dir: &Path) -> Result<()> {
    let keys = list_ssh_keys(ssh_dir)?;
    let state = Arc::new(AppState {
        ssh_dir: ssh_dir.to_path_buf(),
        keys,
    });

    let mut siv = cursive::default();
    siv.set_global_callback('q', |s| s.quit());
    show_file_selection(&mut siv, state);
    siv.run();
    Ok(())
}

fn list_label(key: &SshKeyInfo) -> String {
    let perm_warn = if key.metadata.permissions_secure {
        ""
    } else {
        " [!perm]"
    };

    let encrypted = key
        .details
        .as_ref()
        .map(|d| if d.encrypted { " [enc]" } else { "" })
        .unwrap_or("");

    format!("{}{encrypted}{perm_warn}", key.name)
}

fn show_file_selection(siv: &mut Cursive, state: Arc<AppState>) {
    let mut select = SelectView::new().h_align(HAlign::Left).autojump();
    for (index, key) in state.keys.iter().enumerate() {
        select.add_item(list_label(key), index);
    }

    let state_for_submit = Arc::clone(&state);
    select.set_on_submit(move |siv, index: &usize| {
        show_key_detail(siv, Arc::clone(&state_for_submit), *index);
    });

    siv.add_layer(
        Dialog::around(select.scrollable().fixed_size((60, 12)))
            .title(format!("My SSH Keys ({})", state.ssh_dir.display()))
            .button("Quit (q)", |s| s.quit()),
    );
}

fn show_key_detail(siv: &mut Cursive, state: Arc<AppState>, index: usize) {
    let Some(key) = state.keys.get(index).cloned() else {
        return;
    };

    siv.pop_layer();

    let public_key = key
        .details
        .as_ref()
        .and_then(|d| d.public_key.as_ref())
        .map(|k| k.trim().to_string());
    let private_key_path = key.path.clone();

    let state_for_back = Arc::clone(&state);
    siv.add_layer(
        Dialog::around(
            TextView::new(format_key_detail(&key, false))
                .scrollable()
                .fixed_size((70, 20)),
        )
        .title(key.name.clone())
        .button("Back", move |s| {
            s.pop_layer();
            show_file_selection(s, Arc::clone(&state_for_back));
        })
        .button("Copy Public Key", move |s| {
            let message = match public_key.as_deref() {
                None => "No public key available for this key".to_string(),
                Some(text) => match copy_to_clipboard(text) {
                    Ok(()) => "Public key copied to clipboard".to_string(),
                    Err(err) => format!("Copy failed: {err}"),
                },
            };

            s.add_layer(Dialog::info(message));
        })
        .button("Show Private Key", move |s| {
            let content = std::fs::read_to_string(&private_key_path)
                .unwrap_or_else(|err| format!("Unable to read private key: {err}"));

            s.add_layer(
                Dialog::around(TextView::new(content).scrollable().fixed_size((70, 20)))
                    .title("Private Key")
                    .dismiss_button("Close"),
            );
        })
        .button("Quit (q)", |s| s.quit()),
    );
}

fn copy_to_clipboard(text: &str) -> Result<()> {
    arboard::Clipboard::new()
        .map_err(|err| MySshError::ClipboardError(err.to_string()))?
        .set_text(text)
        .map_err(|err| MySshError::ClipboardError(err.to_string()))
}
