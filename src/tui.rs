use crate::error::{MySshError, Result};
use crate::keys::{find_key, list_ssh_keys, SshKeyInfo};
use cursive::align::HAlign;
use cursive::traits::*;
use cursive::views::{Dialog, SelectView, TextView};
use cursive::Cursive;
use std::path::Path;
use std::sync::{Arc, Mutex};

struct AppState {
    ssh_dir: std::path::PathBuf,
    keys: Vec<SshKeyInfo>,
}

pub fn run(ssh_dir: &Path) -> Result<()> {
    let keys = list_ssh_keys(ssh_dir)?;
    let state = Arc::new(Mutex::new(AppState {
        ssh_dir: ssh_dir.to_path_buf(),
        keys,
    }));

    let mut siv = cursive::default();
    siv.set_global_callback('q', |s| s.quit());
    show_file_selection(&mut siv, Arc::clone(&state));
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

    format!("{}{}{}", key.name, encrypted, perm_warn)
}

fn show_file_selection(siv: &mut Cursive, state: Arc<Mutex<AppState>>) {
    let keys = state.lock().unwrap().keys.clone();
    let ssh_dir_display = state.lock().unwrap().ssh_dir.display().to_string();

    let mut select = SelectView::new().h_align(HAlign::Left).autojump();
    for key in &keys {
        select.add_item(list_label(key), key.path.clone());
    }

    let state_for_submit = Arc::clone(&state);
    select.set_on_submit(move |siv, path| {
        show_key_detail(siv, Arc::clone(&state_for_submit), path);
    });

    siv.add_layer(
        Dialog::around(select.scrollable().fixed_size((60, 12)))
            .title(format!("My SSH Keys ({ssh_dir_display})"))
            .button("Quit (q)", |s| s.quit()),
    );
}

fn show_key_detail(siv: &mut Cursive, state: Arc<Mutex<AppState>>, file_path: &str) {
    siv.pop_layer();

    let key = state
        .lock()
        .unwrap()
        .keys
        .iter()
        .find(|k| k.path == file_path)
        .cloned()
        .or_else(|| find_key(&state.lock().unwrap().ssh_dir, file_path).ok());

    let content = match &key {
        Some(k) => format_detail_view(k),
        None => format!("Unable to load key: {file_path}"),
    };

    let copy_content = key
        .as_ref()
        .and_then(|k| k.details.as_ref())
        .and_then(|d| d.public_key.clone())
        .unwrap_or_else(|| content.clone());

    let title = key
        .as_ref()
        .map(|k| k.name.clone())
        .unwrap_or_else(|| "Key Detail".to_string());

    let state_for_back = Arc::clone(&state);
    siv.add_layer(
        Dialog::around(TextView::new(content).scrollable().fixed_size((70, 20)))
            .title(title)
            .button("Back", move |s| {
                s.pop_layer();
                show_file_selection(s, Arc::clone(&state_for_back));
            })
            .button("Copy Public Key", move |s| {
                match copy_to_clipboard(&copy_content) {
                    Ok(()) => {
                        s.add_layer(Dialog::info("Public key copied to clipboard"));
                    }
                    Err(err) => {
                        s.add_layer(Dialog::info(format!("Copy failed: {err}")));
                    }
                }
            })
            .button("Quit (q)", |s| s.quit()),
    );
}

fn format_detail_view(key: &SshKeyInfo) -> String {
    let mut output = String::new();

    output.push_str(&format!("Path: {}\n", key.path));
    output.push_str(&format!("Size: {} bytes\n", key.metadata.size_bytes));

    if let Some(modified) = &key.metadata.modified {
        output.push_str(&format!("Modified: {modified}\n"));
    }

    output.push_str(&format!("Permissions: {}", key.metadata.permissions));
    if !key.metadata.permissions_secure {
        output.push_str(" (WARNING: too permissive — recommend chmod 600)");
    }
    output.push_str("\n\n");

    if let Some(details) = &key.details {
        output.push_str(&format!("Algorithm: {}\n", details.algorithm));
        output.push_str(&format!("Fingerprint (SHA256): {}\n", details.fingerprint));
        output.push_str(&format!(
            "Passphrase: {}\n",
            if details.encrypted {
                "encrypted"
            } else {
                "not encrypted"
            }
        ));

        if let Some(comment) = &details.comment {
            output.push_str(&format!("Comment: {comment}\n"));
        }

        if let Some(pub_path) = &details.public_key_path {
            output.push_str(&format!("\nPublic key file: {pub_path}\n"));
        }

        if let Some(public_key) = &details.public_key {
            output.push_str("\n--- Public Key ---\n");
            output.push_str(public_key.trim());
            output.push('\n');
        }
    }

    if let Ok(contents) = std::fs::read_to_string(&key.path) {
        output.push_str("\n--- Private Key ---\n");
        output.push_str(contents.trim_end());
        output.push('\n');
    }

    output
}

fn copy_to_clipboard(text: &str) -> Result<()> {
    let public_key = extract_public_key_section(text);
    arboard::Clipboard::new()
        .map_err(|err| MySshError::ClipboardError(err.to_string()))?
        .set_text(public_key)
        .map_err(|err| MySshError::ClipboardError(err.to_string()))
}

fn extract_public_key_section(text: &str) -> String {
    if let Some(start) = text.find("--- Public Key ---") {
        let rest = &text[start + "--- Public Key ---".len()..];
        if let Some(end) = rest.find("--- Private Key ---") {
            return rest[..end].trim().to_string();
        }
        return rest.trim().to_string();
    }

    if text.starts_with("ssh-") {
        return text.lines().next().unwrap_or(text).trim().to_string();
    }

    text.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::extract_public_key_section;

    #[test]
    fn extracts_public_key_from_detail_view() {
        let text =
            "meta\n--- Public Key ---\nssh-ed25519 AAAAC3 comment\n--- Private Key ---\nsecret";
        assert_eq!(
            extract_public_key_section(text),
            "ssh-ed25519 AAAAC3 comment"
        );
    }
}
