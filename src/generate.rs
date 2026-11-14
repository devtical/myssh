use crate::cli::KeyAlgorithm;
use crate::error::{MySshError, Result};
use crate::keys::{
    ensure_private_dir, find_key, looks_like_private_key, public_key_path, set_mode,
    should_show_file_name,
};
use ssh_key::{Algorithm, LineEnding, PrivateKey, PublicKey};
use std::fs;
use std::path::{Path, PathBuf};

impl KeyAlgorithm {
    pub fn default_file_name(&self) -> &'static str {
        match self {
            Self::Ed25519 => "id_ed25519",
            Self::Rsa => "id_rsa",
            Self::Ecdsa => "id_ecdsa",
        }
    }

    fn to_ssh_algorithm(&self) -> Algorithm {
        match self {
            Self::Ed25519 => Algorithm::Ed25519,
            Self::Rsa => Algorithm::Rsa {
                hash: Some(ssh_key::HashAlg::Sha256),
            },
            Self::Ecdsa => Algorithm::Ecdsa {
                curve: ssh_key::EcdsaCurve::NistP256,
            },
        }
    }
}

fn validate_key_name(name: &str) -> Result<()> {
    let invalid = |reason: &str| {
        Err(MySshError::General(format!(
            "Invalid key name `{name}`: {reason}"
        )))
    };

    if name.is_empty() {
        return invalid("name is empty");
    }

    if name.contains('/') || name.contains('\\') {
        return invalid("must be a file name, not a path");
    }

    if name.starts_with('.') {
        return invalid("must not start with a dot");
    }

    if name.ends_with(".pub") {
        return invalid("must not end with .pub");
    }

    Ok(())
}

fn ensure_absent(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }

    Err(MySshError::General(format!(
        "File already exists: {}",
        path.display()
    )))
}

fn copy_file(from: &Path, to: &Path, mode: u32) -> Result<()> {
    fs::copy(from, to).map_err(|err| MySshError::WriteError {
        path: to.to_path_buf(),
        source: err.to_string(),
    })?;

    set_mode(to, mode)
}

pub fn generate_key(
    ssh_dir: &Path,
    algorithm: KeyAlgorithm,
    name: Option<&str>,
    comment: Option<&str>,
    passphrase: Option<&str>,
) -> Result<()> {
    let name = name.unwrap_or(algorithm.default_file_name());
    validate_key_name(name)?;

    let private_path = ssh_dir.join(name);
    let pub_path = public_key_path(&private_path);
    ensure_absent(&private_path)?;
    ensure_absent(&pub_path)?;

    ensure_private_dir(ssh_dir)?;

    let mut rng = rand_core::OsRng;
    let mut private_key = PrivateKey::random(&mut rng, algorithm.to_ssh_algorithm())
        .map_err(|err| MySshError::General(err.to_string()))?;
    private_key.set_comment(comment.unwrap_or("myssh-generated"));

    let public_key: PublicKey = private_key.public_key().clone();

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
    set_mode(&private_path, 0o600)?;

    public_key
        .write_openssh_file(&pub_path)
        .map_err(|err| MySshError::WriteError {
            path: pub_path.clone(),
            source: err.to_string(),
        })?;
    set_mode(&pub_path, 0o644)?;

    println!("Generated key pair:");
    println!("  Private: {}", private_path.display());
    println!("  Public:  {}", pub_path.display());
    Ok(())
}

pub fn export_key(ssh_dir: &Path, key_name: &str, dest: &Path) -> Result<()> {
    let key = find_key(ssh_dir, key_name)?;
    let private_src = PathBuf::from(&key.path);
    let public_src = public_key_path(&private_src);

    let private_dest = dest.join(&key.name);
    let public_dest = public_key_path(&private_dest);
    ensure_absent(&private_dest)?;
    if public_src.exists() {
        ensure_absent(&public_dest)?;
    }

    ensure_private_dir(dest)?;

    copy_file(&private_src, &private_dest, 0o600)?;

    if public_src.exists() {
        copy_file(&public_src, &public_dest, 0o644)?;
    }

    println!("Exported {} to {}", key.name, dest.display());
    Ok(())
}

fn is_private_key_file(path: &Path) -> bool {
    let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };

    if !path.is_file() || !should_show_file_name(file_name) {
        return false;
    }

    fs::read_to_string(path)
        .map(|contents| looks_like_private_key(&contents))
        .unwrap_or(false)
}

fn select_import_source(src: &Path, name: Option<&str>) -> Result<PathBuf> {
    if let Some(target_name) = name {
        validate_key_name(target_name)?;

        let path = src.join(target_name);
        if !is_private_key_file(&path) {
            return Err(MySshError::KeyNotFound {
                name: path.display().to_string(),
            });
        }

        return Ok(path);
    }

    let mut candidates: Vec<PathBuf> = fs::read_dir(src)
        .map_err(|err| MySshError::ReadError {
            path: src.to_path_buf(),
            source: err.to_string(),
        })?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| is_private_key_file(path))
        .collect();

    candidates.sort();

    match candidates.len() {
        0 => Err(MySshError::General(format!(
            "No private key found in {}",
            src.display()
        ))),
        1 => Ok(candidates.remove(0)),
        _ => {
            let names: Vec<String> = candidates
                .iter()
                .filter_map(|p| p.file_name()?.to_str().map(str::to_string))
                .collect();

            Err(MySshError::General(format!(
                "Multiple private keys found in {} ({}); choose one with --name",
                src.display(),
                names.join(", ")
            )))
        }
    }
}

pub fn import_key(ssh_dir: &Path, src: &Path, name: Option<&str>) -> Result<()> {
    if !src.is_dir() {
        return Err(MySshError::General(format!(
            "Source is not a directory: {}",
            src.display()
        )));
    }

    let private_src = select_import_source(src, name)?;
    let public_src = public_key_path(&private_src);

    let file_name = private_src
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| MySshError::General("Invalid file name".to_string()))?;

    let private_dest = ssh_dir.join(file_name);
    let public_dest = public_key_path(&private_dest);
    ensure_absent(&private_dest)?;
    if public_src.exists() {
        ensure_absent(&public_dest)?;
    }

    ensure_private_dir(ssh_dir)?;

    copy_file(&private_src, &private_dest, 0o600)?;

    if public_src.exists() {
        copy_file(&public_src, &public_dest, 0o644)?;
    }

    println!("Imported {} to {}", file_name, ssh_dir.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const FAKE_KEY: &str =
        "-----BEGIN OPENSSH PRIVATE KEY-----\nnot-really-a-key\n-----END OPENSSH PRIVATE KEY-----\n";

    #[test]
    fn generate_uses_algorithm_default_name() {
        let dir = TempDir::new().unwrap();

        generate_key(dir.path(), KeyAlgorithm::Ecdsa, None, None, None).unwrap();

        assert!(dir.path().join("id_ecdsa").is_file());
        assert!(dir.path().join("id_ecdsa.pub").is_file());
        assert!(!dir.path().join("id_ed25519").exists());
    }

    #[test]
    fn generate_refuses_existing_key() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("id_ed25519"), FAKE_KEY).unwrap();

        let result = generate_key(dir.path(), KeyAlgorithm::Ed25519, None, None, None);

        assert!(result.is_err());
    }

    #[test]
    fn generate_rejects_path_like_names() {
        let dir = TempDir::new().unwrap();

        for name in ["../escape", "sub/key", ".hidden", "key.pub", ""] {
            let result = generate_key(dir.path(), KeyAlgorithm::Ed25519, Some(name), None, None);
            assert!(result.is_err(), "name `{name}` should be rejected");
        }
    }

    #[test]
    fn generated_encrypted_key_is_detected() {
        let dir = TempDir::new().unwrap();

        generate_key(
            dir.path(),
            KeyAlgorithm::Ed25519,
            Some("k"),
            None,
            Some("secret"),
        )
        .unwrap();

        let key = find_key(dir.path(), "k").unwrap();
        let details = key.details.unwrap();
        assert!(details.encrypted);
        assert!(details.fingerprint.starts_with("SHA256:"));
    }

    #[test]
    fn import_ignores_non_key_files() {
        let src = TempDir::new().unwrap();
        let ssh_dir = TempDir::new().unwrap();
        fs::write(src.path().join(".DS_Store"), "junk").unwrap();
        fs::write(src.path().join("config"), "Host x\n").unwrap();
        fs::write(src.path().join("notes.txt"), "hello").unwrap();
        fs::write(src.path().join("zz_key"), FAKE_KEY).unwrap();

        import_key(ssh_dir.path(), src.path(), None).unwrap();

        assert!(ssh_dir.path().join("zz_key").is_file());
        assert!(!ssh_dir.path().join(".DS_Store").exists());
    }

    #[test]
    fn import_requires_name_when_ambiguous() {
        let src = TempDir::new().unwrap();
        let ssh_dir = TempDir::new().unwrap();
        fs::write(src.path().join("key_a"), FAKE_KEY).unwrap();
        fs::write(src.path().join("key_b"), FAKE_KEY).unwrap();

        assert!(import_key(ssh_dir.path(), src.path(), None).is_err());

        import_key(ssh_dir.path(), src.path(), Some("key_b")).unwrap();
        assert!(ssh_dir.path().join("key_b").is_file());
    }

    #[test]
    fn export_refuses_to_overwrite() {
        let ssh_dir = TempDir::new().unwrap();
        let dest = TempDir::new().unwrap();
        fs::write(ssh_dir.path().join("id_test"), FAKE_KEY).unwrap();
        fs::write(dest.path().join("id_test"), "existing").unwrap();

        assert!(export_key(ssh_dir.path(), "id_test", dest.path()).is_err());
        assert_eq!(
            fs::read_to_string(dest.path().join("id_test")).unwrap(),
            "existing"
        );
    }

    #[cfg(unix)]
    #[test]
    fn imported_private_key_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let src = TempDir::new().unwrap();
        let ssh_dir = TempDir::new().unwrap();
        let key_path = src.path().join("id_test");
        fs::write(&key_path, FAKE_KEY).unwrap();
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644)).unwrap();

        import_key(ssh_dir.path(), src.path(), None).unwrap();

        let mode = fs::metadata(ssh_dir.path().join("id_test"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
