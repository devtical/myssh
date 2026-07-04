use crate::cli::KeyAlgorithm;
use crate::error::{MySshError, Result};
use crate::keys::{find_key, public_key_path};
use ssh_key::{Algorithm, LineEnding, PrivateKey, PublicKey};
use std::fs;
use std::path::{Path, PathBuf};

pub fn generate_key(
    ssh_dir: &Path,
    algorithm: KeyAlgorithm,
    name: &str,
    comment: Option<&str>,
    passphrase: Option<&str>,
) -> Result<()> {
    fs::create_dir_all(ssh_dir).map_err(|err| MySshError::WriteError {
        path: ssh_dir.to_path_buf(),
        source: err.to_string(),
    })?;

    let private_path = ssh_dir.join(name);
    if private_path.exists() {
        return Err(MySshError::General(format!(
            "Key already exists: {}",
            private_path.display()
        )));
    }

    let pub_path = public_key_path(&private_path);
    if pub_path.exists() {
        return Err(MySshError::General(format!(
            "Public key already exists: {}",
            pub_path.display()
        )));
    }

    let ssh_algorithm = match algorithm {
        KeyAlgorithm::Ed25519 => Algorithm::Ed25519,
        KeyAlgorithm::Rsa => Algorithm::Rsa {
            hash: Some(ssh_key::HashAlg::Sha256),
        },
        KeyAlgorithm::Ecdsa => Algorithm::Ecdsa {
            curve: ssh_key::EcdsaCurve::NistP256,
        },
    };

    let mut rng = rand_core::OsRng;
    let comment_text = comment.unwrap_or("myssh-generated");
    let mut private_key = PrivateKey::random(&mut rng, ssh_algorithm)
        .map_err(|err| MySshError::General(err.to_string()))?;
    private_key.set_comment(comment_text);

    if let Some(pass) = passphrase {
        private_key = private_key
            .encrypt(&mut rng, pass.as_bytes())
            .map_err(|err| MySshError::General(err.to_string()))?;
    }

    private_key
        .write_openssh_file(&private_path, LineEnding::LF)
        .map_err(|err| MySshError::WriteError {
            path: private_path.clone(),
            source: err.to_string(),
        })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&private_path, fs::Permissions::from_mode(0o600)).map_err(|err| {
            MySshError::WriteError {
                path: private_path.clone(),
                source: err.to_string(),
            }
        })?;
    }

    let public_key: PublicKey = (&private_key).into();
    public_key
        .write_openssh_file(&pub_path)
        .map_err(|err| MySshError::WriteError {
            path: pub_path.clone(),
            source: err.to_string(),
        })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&pub_path, fs::Permissions::from_mode(0o644)).map_err(|err| {
            MySshError::WriteError {
                path: pub_path.clone(),
                source: err.to_string(),
            }
        })?;
    }

    println!("Generated key pair:");
    println!("  Private: {}", private_path.display());
    println!("  Public:  {}", pub_path.display());
    Ok(())
}

pub fn export_key(ssh_dir: &Path, key_name: &str, dest: &Path) -> Result<()> {
    let key = find_key(ssh_dir, key_name)?;
    let private_src = PathBuf::from(&key.path);
    let public_src = public_key_path(&private_src);

    fs::create_dir_all(dest).map_err(|err| MySshError::WriteError {
        path: dest.to_path_buf(),
        source: err.to_string(),
    })?;

    let private_dest = dest.join(&key.name);
    fs::copy(&private_src, &private_dest).map_err(|err| MySshError::WriteError {
        path: private_dest.clone(),
        source: err.to_string(),
    })?;

    if public_src.exists() {
        let pub_name = format!("{}.pub", key.name);
        let public_dest = dest.join(pub_name);
        fs::copy(&public_src, &public_dest).map_err(|err| MySshError::WriteError {
            path: public_dest,
            source: err.to_string(),
        })?;
    }

    println!("Exported {} to {}", key.name, dest.display());
    Ok(())
}

pub fn import_key(ssh_dir: &Path, src: &Path, name: Option<&str>) -> Result<()> {
    if !src.is_dir() {
        return Err(MySshError::General(format!(
            "Source is not a directory: {}",
            src.display()
        )));
    }

    let entries: Vec<PathBuf> = fs::read_dir(src)
        .map_err(|err| MySshError::ReadError {
            path: src.to_path_buf(),
            source: err.to_string(),
        })?
        .filter_map(|entry| entry.ok())
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .collect();

    let private_file = if let Some(target_name) = name {
        entries
            .iter()
            .find(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n == target_name)
                    .unwrap_or(false)
            })
            .cloned()
            .ok_or_else(|| MySshError::KeyNotFound {
                name: target_name.to_string(),
            })?
    } else {
        entries
            .iter()
            .find(|p| {
                p.extension().map(|ext| ext != "pub").unwrap_or(true)
                    && !p.to_string_lossy().ends_with(".pub")
            })
            .cloned()
            .ok_or_else(|| {
                MySshError::General(format!("No private key found in {}", src.display()))
            })?
    };

    let file_name = private_file
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| MySshError::General("Invalid file name".to_string()))?;

    fs::create_dir_all(ssh_dir).map_err(|err| MySshError::WriteError {
        path: ssh_dir.to_path_buf(),
        source: err.to_string(),
    })?;

    let dest_private = ssh_dir.join(file_name);
    if dest_private.exists() {
        return Err(MySshError::General(format!(
            "Key already exists: {}",
            dest_private.display()
        )));
    }

    fs::copy(&private_file, &dest_private).map_err(|err| MySshError::WriteError {
        path: dest_private.clone(),
        source: err.to_string(),
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dest_private, fs::Permissions::from_mode(0o600)).ok();
    }

    let public_src = public_key_path(&private_file);
    if public_src.exists() {
        let dest_public = public_key_path(&dest_private);
        fs::copy(&public_src, &dest_public).map_err(|err| MySshError::WriteError {
            path: dest_public,
            source: err.to_string(),
        })?;
    }

    println!("Imported {} to {}", file_name, ssh_dir.display());
    Ok(())
}
