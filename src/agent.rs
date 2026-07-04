use crate::error::{MySshError, Result};
use crate::keys::find_key;
use std::path::Path;
use std::process::Command;

pub fn add_key(ssh_dir: &Path, key_name: &str) -> Result<()> {
    let key = find_key(ssh_dir, key_name)?;
    #[cfg(target_os = "macos")]
    run_ssh_add(&["-K", &key.path])?;
    #[cfg(not(target_os = "macos"))]
    run_ssh_add(&[&key.path])?;
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
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("The agent has no identities")
            || stderr.contains("could not open a connection")
        {
            println!("No keys loaded in ssh-agent");
            Ok(())
        } else {
            Err(MySshError::CommandError(stderr.to_string()))
        }
    }
}

fn run_ssh_add(args: &[&str]) -> Result<()> {
    let output = Command::new("ssh-add")
        .args(args)
        .output()
        .map_err(|err| MySshError::CommandError(format!("Failed to run ssh-add: {err}")))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(MySshError::CommandError(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }
}
