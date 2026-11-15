use crate::agent;
use crate::error::{MySshError, Result};
use crate::generate;
use crate::keys::{find_key, format_key_detail, list_ssh_keys, resolve_ssh_dir, SshKeyInfo};
use clap::{Parser, Subcommand, ValueEnum};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "myssh",
    about = "Inspect and manage SSH keys in your .ssh directory",
    version
)]
pub struct Cli {
    /// Custom SSH directory path
    #[arg(long, env = "MYSSH_DIR", global = true)]
    pub ssh_dir: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// List SSH private keys
    List {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Show key details
    Show {
        /// Key file name or path
        key: String,
        /// Also print the private key contents
        #[arg(long)]
        private: bool,
    },
    /// Show key fingerprint
    Fingerprint {
        /// Key file name or path
        key: String,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Generate a new SSH key pair
    Generate {
        /// Key algorithm
        #[arg(long, value_enum, default_value_t = KeyAlgorithm::Ed25519)]
        algorithm: KeyAlgorithm,
        /// Output file name [default: id_<algorithm>]
        #[arg(long)]
        name: Option<String>,
        /// Comment for the key
        #[arg(long)]
        comment: Option<String>,
        /// Protect the key with a passphrase (prompted, or read from MYSSH_PASSPHRASE)
        #[arg(long)]
        passphrase: bool,
    },
    /// Add a key to the ssh-agent
    Add {
        /// Key file name or path
        key: String,
    },
    /// Remove a key from the ssh-agent
    Remove {
        /// Key file name or path
        key: String,
    },
    /// List keys loaded in ssh-agent
    AgentList,
    /// Export a key pair to a directory
    Export {
        /// Key file name or path
        key: String,
        /// Destination directory
        dest: PathBuf,
    },
    /// Import a key pair from a directory
    Import {
        /// Source directory containing key files
        src: PathBuf,
        /// Name of the private key file in the source directory (required if it has several)
        #[arg(long)]
        name: Option<String>,
    },
}

#[derive(Clone, ValueEnum)]
pub enum KeyAlgorithm {
    Ed25519,
    Rsa,
    Ecdsa,
}

pub fn run(cli: Cli) -> Result<()> {
    let ssh_dir = resolve_ssh_dir(cli.ssh_dir.as_deref())?;

    match cli.command {
        None => crate::tui::run(&ssh_dir),
        Some(Commands::List { json }) => cmd_list(&ssh_dir, json),
        Some(Commands::Show { key, private }) => cmd_show(&ssh_dir, &key, private),
        Some(Commands::Fingerprint { key, json }) => cmd_fingerprint(&ssh_dir, &key, json),
        Some(Commands::Generate {
            algorithm,
            name,
            comment,
            passphrase,
        }) => {
            let passphrase = passphrase.then(read_passphrase).transpose()?;

            generate::generate_key(
                &ssh_dir,
                algorithm,
                name.as_deref(),
                comment.as_deref(),
                passphrase.as_deref(),
            )
        }
        Some(Commands::Add { key }) => agent::add_key(&ssh_dir, &key),
        Some(Commands::Remove { key }) => agent::remove_key(&ssh_dir, &key),
        Some(Commands::AgentList) => agent::list_agent_keys(),
        Some(Commands::Export { key, dest }) => generate::export_key(&ssh_dir, &key, &dest),
        Some(Commands::Import { src, name }) => {
            generate::import_key(&ssh_dir, &src, name.as_deref())
        }
    }
}

fn read_passphrase() -> Result<String> {
    if let Ok(passphrase) = std::env::var("MYSSH_PASSPHRASE") {
        return non_empty_passphrase(passphrase);
    }

    let prompt_error =
        |err: std::io::Error| MySshError::General(format!("Unable to read passphrase: {err}"));

    let passphrase = rpassword::prompt_password("Enter passphrase: ").map_err(prompt_error)?;
    let confirmation = rpassword::prompt_password("Confirm passphrase: ").map_err(prompt_error)?;

    if passphrase != confirmation {
        return Err(MySshError::General("Passphrases do not match".to_string()));
    }

    non_empty_passphrase(passphrase)
}

fn non_empty_passphrase(passphrase: String) -> Result<String> {
    if passphrase.is_empty() {
        return Err(MySshError::General(
            "Passphrase must not be empty".to_string(),
        ));
    }

    Ok(passphrase)
}

fn to_json<T: serde::Serialize>(value: &T) -> Result<String> {
    serde_json::to_string_pretty(value).map_err(|err| MySshError::General(err.to_string()))
}

fn cmd_list(ssh_dir: &Path, json: bool) -> Result<()> {
    let keys = list_ssh_keys(ssh_dir)?;

    if json {
        println!("{}", to_json(&keys)?);
        return Ok(());
    }

    for key in &keys {
        print_list_line(key);
    }

    Ok(())
}

fn print_list_line(key: &SshKeyInfo) {
    let details = key.details.as_ref();
    let algorithm = details.map(|d| d.algorithm.as_str()).unwrap_or("Unknown");
    let fingerprint = details.map(|d| d.fingerprint.as_str()).unwrap_or("N/A");
    let encrypted = details.map(|d| d.encrypted).unwrap_or(false);
    let secure = if key.metadata.permissions_secure {
        "ok"
    } else {
        "WARN"
    };

    println!(
        "{name}\t{algorithm}\t{fingerprint}\tencrypted={encrypted}\tperm={secure}",
        name = key.name,
    );
}

fn cmd_show(ssh_dir: &Path, key_name: &str, include_private: bool) -> Result<()> {
    let key = find_key(ssh_dir, key_name)?;
    print!("{}", format_key_detail(&key, include_private));
    Ok(())
}

fn cmd_fingerprint(ssh_dir: &Path, key_name: &str, json: bool) -> Result<()> {
    let key = find_key(ssh_dir, key_name)?;

    let details = key
        .details
        .as_ref()
        .filter(|d| d.fingerprint != "N/A")
        .ok_or_else(|| MySshError::ParseError {
            path: PathBuf::from(&key.path),
            source: "Unable to determine fingerprint".to_string(),
        })?;

    if !json {
        println!("{}", details.fingerprint);
        return Ok(());
    }

    #[derive(serde::Serialize)]
    struct FingerprintOutput<'a> {
        name: &'a str,
        path: &'a str,
        algorithm: &'a str,
        fingerprint: &'a str,
        encrypted: bool,
    }

    let output = FingerprintOutput {
        name: &key.name,
        path: &key.path,
        algorithm: &details.algorithm,
        fingerprint: &details.fingerprint,
        encrypted: details.encrypted,
    };
    println!("{}", to_json(&output)?);

    Ok(())
}
