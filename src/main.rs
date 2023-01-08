use cursive::align::HAlign;
use cursive::traits::*;
use cursive::views::{Dialog, SelectView, TextView};
use cursive::Cursive;
use std::fs;
use std::path::Path;

fn main() {
    let home = std::env::var("HOME").unwrap();
    let path = Path::new(&home).join(".ssh");
    let mut arr = Vec::new();

    for entry in fs::read_dir(path).expect("Unable to list") {
        let entry = entry.expect("unable to get entry");
        let path = entry.path();
        let str = path.display().to_string();

        if !str.contains("known_hosts") {
            arr.push(str);
        }
    }

    let mut select = SelectView::new().h_align(HAlign::Center).autojump();

    select.add_all_str(arr);
    select.set_on_submit(show_next_window);

    let mut siv = cursive::default();

    siv.add_layer(
        Dialog::around(select.scrollable().fixed_size((40, 10))).title("My Keys"),
    );

    siv.run();
}

fn show_next_window(siv: &mut Cursive, str: &str) {
    siv.pop_layer();

    let contents = fs::read_to_string(str).expect("Should have been able to read the file");
    let text = contents;

    siv.add_layer(Dialog::around(TextView::new(text)).button("Quit", |s| s.quit()));
}
