use cursive::align::HAlign;
use cursive::traits::*;
use cursive::views::{Dialog, SelectView, TextView};
use cursive::Cursive;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    let mut siv = cursive::default();
    show_file_selection(&mut siv);
    siv.run();
}

fn show_file_selection(siv: &mut Cursive) {
    let keys = match list_ssh_files() {
        Ok(keys) => keys,
        Err(err) => {
            siv.add_layer(
                Dialog::text(err)
                    .title("MySSH")
                    .button("Quit", |s| s.quit()),
            );
            return;
        }
    };

    let mut select = SelectView::new().h_align(HAlign::Center).autojump();
    select.add_all_str(keys);
    select.set_on_submit(show_next_window);

    siv.add_layer(
        Dialog::around(select.scrollable().fixed_size((40, 10)))
            .title("My SSH Keys")
            .button("Quit", |s| s.quit()),
    );
}

fn show_next_window(siv: &mut Cursive, file_path: &str) {
    siv.pop_layer();

    let contents = match fs::read_to_string(file_path) {
        Ok(contents) => contents,
        Err(err) => format!("Unable to read file:\n{err}"),
    };
    let text_view = TextView::new(contents);

    siv.add_layer(
        Dialog::around(text_view)
            .button("Back", move |s| {
                s.pop_layer();
                show_file_selection(s);
            })
            .button("Quit", |s| s.quit()),
    );
}

fn list_ssh_files() -> Result<Vec<String>, String> {
    let home =
        std::env::var("HOME").map_err(|_| "HOME environment variable not set".to_string())?;
    let ssh_path = Path::new(&home).join(".ssh");
    let entries = fs::read_dir(&ssh_path)
        .map_err(|err| format!("Unable to list {}: {err}", ssh_path.display()))?;

    let mut keys: Vec<String> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| should_show_entry(path))
        .map(|path| path.display().to_string())
        .collect();

    keys.sort();

    if keys.is_empty() {
        return Err(format!("No SSH key files found in {}", ssh_path.display()));
    }

    Ok(keys)
}

fn should_show_entry(path: &PathBuf) -> bool {
    if !path.is_file() {
        return false;
    }

    let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };

    should_show_file_name(file_name)
}

fn should_show_file_name(file_name: &str) -> bool {
    let excluded = [
        "known_hosts",
        "known_hosts.old",
        "authorized_keys",
        "config",
    ];

    if excluded.contains(&file_name) {
        return false;
    }

    !file_name.ends_with(".pub")
}

#[cfg(test)]
mod tests {
    use super::should_show_file_name;

    #[test]
    fn excludes_known_hosts() {
        assert!(!should_show_file_name("known_hosts"));
    }

    #[test]
    fn excludes_public_keys() {
        assert!(!should_show_file_name("id_rsa.pub"));
    }

    #[test]
    fn includes_private_key_like_name() {
        assert!(should_show_file_name("id_ed25519"));
    }
}
