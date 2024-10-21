use cursive::align::HAlign;
use cursive::traits::*;
use cursive::views::{Dialog, SelectView, TextView};
use cursive::Cursive;
use std::fs;
use std::path::Path;

fn main() {
    let mut siv = cursive::default();
    show_file_selection(&mut siv);
    siv.run();
}

fn show_file_selection(siv: &mut Cursive) {
    let home = std::env::var("HOME").expect("HOME environment variable not set");
    let ssh_path = Path::new(&home).join(".ssh");
    let mut keys = Vec::new();

    for entry in fs::read_dir(&ssh_path).expect("Unable to list directory") {
        let entry = entry.expect("Unable to read entry");
        let path = entry.path();
        let file_path = path.display().to_string();

        if !file_path.contains("known_hosts") {
            keys.push(file_path);
        }
    }

    let mut select = SelectView::new().h_align(HAlign::Center).autojump();
    select.add_all_str(keys);
    select.set_on_submit(show_next_window);

    siv.add_layer(
        Dialog::around(select.scrollable().fixed_size((40, 10)))
            .title("My SSH Keys")
            .button("Quit", |s| s.quit())
    );
}

fn show_next_window(siv: &mut Cursive, file_path: &str) {
    siv.pop_layer();

    let contents = fs::read_to_string(file_path).expect("Unable to read the file");
    let text_view = TextView::new(contents);

    siv.add_layer(
        Dialog::around(text_view)
            .button("Back", move |s| {
                s.pop_layer();
                show_file_selection(s);
            })
            .button("Quit", |s| s.quit())
    );
}
