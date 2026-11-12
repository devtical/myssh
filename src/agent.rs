use crate::error::{MySshError, Result};
use crate::keys::find_key;
use std::path::Path;
use std::process::Command;

pub fn add_key(ssh_dir: &Path, key_name: &str) -> Result<()> {
    let key = find_key(ssh_dir, key_name)?;
    add_to_agent(&key.path)?;
    println!("Added {} to ssh-agent", key.name);
    Ok(())
}

pub fn remove_key(ssh_dir: &Path, key_name: &str) -> Result<()> {
    let key = find_key(ssh_dir, key_name)?;
    run_ssh_add(&["-d", &key.path])?;
    println!("Removed {} from ssh-agent", key.name);
    Ok(())
}

pub fn list_agent_keys() -> Result<()> {
    let output = Command::new("ssh-add")
        .arg("-l")
        .output()
        .map_err(|err| MySshError::CommandError(format!("Failed to run ssh-add: {err}")))?;

    if output.status.success() {
        print!("{}", String::from_utf8_lossy(&output.stdout));
        return Ok(());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if stdout.contains("The agent has no identities")
        || stderr.contains("The agent has no identities")
    {
        println!("No keys loaded in ssh-agent");
        return Ok(());
    }

    if stderr.contains("could not open a connection")
        || stderr.contains("Could not open a connection")
    {
        return Err(MySshError::CommandError(
            "ssh-agent is not running (SSH_AUTH_SOCK is not set or invalid)".to_string(),
        ));
    }

    Err(MySshError::CommandError(stderr.trim().to_string()))
}

/// On macOS, store the passphrase in the Keychain with `--apple-use-keychain`
/// (the replacement for the deprecated `-K`). Non-Apple builds of OpenSSH,
/// such as Homebrew's, reject that flag, so fall back to a plain `ssh-add`.
#[cfg(target_os = "macos")]
fn add_to_agent(path: &str) -> Result<()> {
    match run_ssh_add(&["--apple-use-keychain", path]) {
        Err(MySshError::CommandError(message)) if is_unsupported_option(&message) => {
            run_ssh_add(&[path])
        }
        result => result,
    }
}

#[cfg(not(target_os = "macos"))]
fn add_to_agent(path: &str) -> Result<()> {
    run_ssh_add(&[path])
}

#[cfg(target_os = "macos")]
fn is_unsupported_option(message: &str) -> bool {
    message.contains("illegal option")
        || message.contains("unknown option")
        || message.contains("unrecognized option")
        || message.starts_with("usage:")
}

fn run_ssh_add(args: &[&str]) -> Result<()> {
    let output = Command::new("ssh-add")
        .args(args)
        .output()
        .map_err(|err| MySshError::CommandError(format!("Failed to run ssh-add: {err}")))?;

    if output.status.success() {
        return Ok(());
    }

    Err(MySshError::CommandError(
        String::from_utf8_lossy(&output.stderr).trim().to_string(),
    ))
}
