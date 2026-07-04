use clap::Parser;
use myssh::Cli;

fn main() {
    let cli = Cli::parse();

    if let Err(err) = myssh::cli::run(cli) {
        eprintln!("Error: {err}");
        std::process::exit(err.exit_code());
    }
}
