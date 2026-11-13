use crate::error::{MySshError, Result};
use serde::Serialize;
use ssh_key::{Algorithm, HashAlg, PrivateKey, PublicKey};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::SystemTime;

const EXCLUDED_FILES: &[&str] = &[
    "known_hosts",
    "known_hosts.old",
    "authorized_keys",
    "authorized_keys2",
    "config",
    "environment",
    "rc",
];

#[derive(Debug, Clone, Serialize)]
pub struct KeyMetadata {
    pub size_bytes: u64,
    pub modified: Option<String>,
    pub permissions: String,
    pub permissions_secure: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct KeyDetails {
    pub algorithm: String,
    pub fingerprint: String,
    pub comment: Option<String>,
    pub encrypted: bool,
    pub public_key: Option<String>,
    pub public_key_path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SshKeyInfo {
    pub path: String,
    pub name: String,
    pub metadata: KeyMetadata,
    pub details: Option<KeyDetails>,
}

pub fn resolve_ssh_dir(custom: Option<&Path>) -> Result<PathBuf> {
    if let Some(dir) = custom {
        return Ok(dir.to_path_buf());
    }

    let home = std::env::var("HOME").map_err(|_| MySshError::HomeNotSet)?;
    Ok(Path::new(&home).join(".ssh"))
}

pub fn should_show_file_name(file_name: &str) -> bool {
    if file_name.starts_with('.') {
        return false;
    }

    if EXCLUDED_FILES.contains(&file_name) {
        return false;
    }

    !file_name.ends_with(".pub")
}

pub fn looks_like_private_key(contents: &str) -> bool {
    contents.contains("-----BEGIN ") && contents.contains("PRIVATE KEY-----")
}

fn should_show_entry(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }

    let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };

    should_show_file_name(file_name)
}

pub fn public_key_path(private_path: &Path) -> PathBuf {
    let mut pub_path = private_path.as_os_str().to_os_string();
    pub_path.push(".pub");
    PathBuf::from(pub_path)
}

pub fn set_mode(path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|err| {
            MySshError::WriteError {
                path: path.to_path_buf(),
                source: err.to_string(),
            }
        })?;
    }

    #[cfg(not(unix))]
    let _ = (path, mode);

    Ok(())
}

/// Create a directory meant to hold private keys, restricted to the owner (0700).
pub fn ensure_private_dir(dir: &Path) -> Result<()> {
    if dir.is_dir() {
        return Ok(());
    }

    fs::create_dir_all(dir).map_err(|err| MySshError::WriteError {
        path: dir.to_path_buf(),
        source: err.to_string(),
    })?;

    set_mode(dir, 0o700)
}

fn format_permissions(mode: u32) -> String {
    format!("{:o}", mode & 0o777)
}

fn is_secure_permissions(mode: u32) -> bool {
    (mode & 0o077) == 0
}

fn format_system_time(time: SystemTime) -> Option<String> {
    use std::time::UNIX_EPOCH;

    let duration = time.duration_since(UNIX_EPOCH).ok()?;
    let secs = duration.as_secs();

    let days = secs / 86400;
    let seconds = secs % 86400;
    let hours = seconds / 3600;
    let minutes = (seconds % 3600) / 60;
    let secs = seconds % 60;

    let (year, month, day) = days_to_ymd(days);
    Some(format!(
        "{year:04}-{month:02}-{day:02} {hours:02}:{minutes:02}:{secs:02}"
    ))
}

fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    let mut remaining = days as i64;
    let mut year = 1970i64;

    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining < days_in_year {
            break;
        }
        remaining -= days_in_year;
        year += 1;
    }

    let days_in_months: [i64; 12] = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 1i64;
    for &days_in_month in &days_in_months {
        if remaining < days_in_month {
            break;
        }
        remaining -= days_in_month;
        month += 1;
    }

    (year as u64, month as u64, remaining as u64 + 1)
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

pub fn read_metadata(path: &Path) -> Result<KeyMetadata> {
    let meta = fs::metadata(path).map_err(|err| MySshError::ReadError {
        path: path.to_path_buf(),
        source: err.to_string(),
    })?;

    #[cfg(unix)]
    let (permissions, permissions_secure) = {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode();
        (format_permissions(mode), is_secure_permissions(mode))
    };

    #[cfg(not(unix))]
    let (permissions, permissions_secure) = ("unknown".to_string(), true);

    Ok(KeyMetadata {
        size_bytes: meta.len(),
        modified: meta.modified().ok().and_then(format_system_time),
        permissions,
        permissions_secure,
    })
}

fn algorithm_name(algorithm: Algorithm) -> String {
    match algorithm {
        Algorithm::Ed25519 => "Ed25519".to_string(),
        Algorithm::Rsa { hash: _ } => "RSA".to_string(),
        Algorithm::Dsa => "DSA".to_string(),
        Algorithm::Ecdsa { curve } => format!("ECDSA ({curve})"),
        Algorithm::SkEd25519 => "SK-Ed25519 (FIDO)".to_string(),
        Algorithm::SkEcdsaSha2NistP256 => "SK-ECDSA-P256 (FIDO)".to_string(),
        _ => format!("{algorithm:?}"),
    }
}

/// Derive the public key of a non-OpenSSH-format key (e.g. legacy PEM) via `ssh-keygen -y`.
/// Passes an empty passphrase so encrypted keys fail instead of prompting.
fn derive_public_key(private_path: &Path) -> Option<String> {
    let output = Command::new("ssh-keygen")
        .args(["-y", "-P", "", "-f"])
        .arg(private_path)
        .stdin(Stdio::null())
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let public_key = String::from_utf8(output.stdout).ok()?;
    let public_key = public_key.trim();

    (!public_key.is_empty()).then(|| public_key.to_string())
}

fn parse_key_details(private_path: &Path, contents: &str) -> KeyDetails {
    let pub_path = public_key_path(private_path);
    let public_key_path_str = pub_path.exists().then(|| pub_path.display().to_string());

    let public_key_from_file = public_key_path_str
        .as_ref()
        .and_then(|_| fs::read_to_string(&pub_path).ok());

    if let Ok(private_key) = PrivateKey::from_openssh(contents.as_bytes()) {
        let comment = Some(private_key.comment())
            .filter(|c| !c.is_empty())
            .map(str::to_string);

        let public_key = public_key_from_file.or_else(|| {
            private_key
                .public_key()
                .to_openssh()
                .ok()
                .map(|s| s.to_string())
        });

        return KeyDetails {
            algorithm: algorithm_name(private_key.algorithm()),
            fingerprint: private_key.fingerprint(HashAlg::Sha256).to_string(),
            comment,
            encrypted: private_key.is_encrypted(),
            public_key,
            public_key_path: public_key_path_str,
        };
    }

    let encrypted = contents.contains("ENCRYPTED");
    let public_key = public_key_from_file.or_else(|| derive_public_key(private_path));

    if let Some(parsed) = public_key
        .as_deref()
        .and_then(|content| PublicKey::from_openssh(content.trim()).ok())
    {
        let comment = Some(parsed.comment())
            .filter(|c| !c.is_empty())
            .map(str::to_string);

        return KeyDetails {
            algorithm: algorithm_name(parsed.algorithm()),
            fingerprint: parsed.fingerprint(HashAlg::Sha256).to_string(),
            comment,
            encrypted,
            public_key,
            public_key_path: public_key_path_str,
        };
    }

    KeyDetails {
        algorithm: "Unknown".to_string(),
        fingerprint: "N/A".to_string(),
        comment: None,
        encrypted,
        public_key: None,
        public_key_path: public_key_path_str,
    }
}

pub fn inspect_key(path: &Path) -> Result<SshKeyInfo> {
    let contents = fs::read_to_string(path).map_err(|err| MySshError::ReadError {
        path: path.to_path_buf(),
        source: err.to_string(),
    })?;

    if !looks_like_private_key(&contents) {
        return Err(MySshError::ParseError {
            path: path.to_path_buf(),
            source: "not a private key".to_string(),
        });
    }

    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();

    let metadata = read_metadata(path)?;
    let details = Some(parse_key_details(path, &contents));

    Ok(SshKeyInfo {
        path: path.display().to_string(),
        name,
        metadata,
        details,
    })
}

pub fn list_ssh_keys(ssh_dir: &Path) -> Result<Vec<SshKeyInfo>> {
    let entries = fs::read_dir(ssh_dir).map_err(|_| MySshError::SshDirNotFound {
        path: ssh_dir.to_path_buf(),
    })?;

    let mut keys: Vec<SshKeyInfo> = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| should_show_entry(path))
        .filter_map(|path| inspect_key(&path).ok())
        .collect();

    keys.sort_by(|a, b| a.name.cmp(&b.name));

    if keys.is_empty() {
        return Err(MySshError::NoKeysFound {
            path: ssh_dir.to_path_buf(),
        });
    }

    Ok(keys)
}

/// Find a key by exact file name inside `ssh_dir`, or by an explicit path
/// (anything containing a path separator).
pub fn find_key(ssh_dir: &Path, name: &str) -> Result<SshKeyInfo> {
    let not_found = || MySshError::KeyNotFound {
        name: name.to_string(),
    };

    let candidate = Path::new(name);
    if candidate.components().count() > 1 {
        if !candidate.is_file() {
            return Err(not_found());
        }

        return inspect_key(candidate);
    }

    list_ssh_keys(ssh_dir)?
        .into_iter()
        .find(|k| k.name == name)
        .ok_or_else(not_found)
}

pub fn format_key_detail(key: &SshKeyInfo, include_private: bool) -> String {
    let mut output = String::new();

    output.push_str(&format!("Path: {}\n", key.path));
    output.push_str(&format!("Size: {} bytes\n", key.metadata.size_bytes));

    if let Some(modified) = &key.metadata.modified {
        output.push_str(&format!("Modified: {modified} UTC\n"));
    }

    output.push_str(&format!("Permissions: {}", key.metadata.permissions));
    if !key.metadata.permissions_secure {
        output.push_str(" (WARNING: too permissive, run chmod 600)");
    }
    output.push('\n');

    if let Some(details) = &key.details {
        output.push_str(&format!("Algorithm: {}\n", details.algorithm));
        output.push_str(&format!("Fingerprint (SHA256): {}\n", details.fingerprint));
        output.push_str(&format!(
            "Passphrase: {}\n",
            if details.encrypted {
                "encrypted (passphrase protected)"
            } else {
                "not encrypted"
            }
        ));

        if let Some(comment) = &details.comment {
            output.push_str(&format!("Comment: {comment}\n"));
        }

        if let Some(pub_path) = &details.public_key_path {
            output.push_str(&format!("Public key file: {pub_path}\n"));
        }

        if let Some(public_key) = &details.public_key {
            output.push('\n');
            output.push_str("--- Public Key ---\n");
            output.push_str(public_key.trim());
            output.push('\n');
        }
    }

    if !include_private {
        return output;
    }

    if let Ok(contents) = fs::read_to_string(&key.path) {
        output.push('\n');
        output.push_str("--- Private Key ---\n");
        output.push_str(contents.trim_end());
        output.push('\n');
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const FAKE_KEY: &str =
        "-----BEGIN OPENSSH PRIVATE KEY-----\nnot-really-a-key\n-----END OPENSSH PRIVATE KEY-----\n";

    fn ssh_dir_with(files: &[(&str, &str)]) -> TempDir {
        let dir = TempDir::new().unwrap();

        for (name, contents) in files {
            fs::write(dir.path().join(name), contents).unwrap();
        }

        dir
    }

    #[test]
    fn excludes_known_hosts() {
        assert!(!should_show_file_name("known_hosts"));
    }

    #[test]
    fn excludes_public_keys() {
        assert!(!should_show_file_name("id_rsa.pub"));
    }

    #[test]
    fn excludes_hidden_files() {
        assert!(!should_show_file_name(".DS_Store"));
    }

    #[test]
    fn includes_private_key_like_name() {
        assert!(should_show_file_name("id_ed25519"));
    }

    #[test]
    fn list_skips_files_that_are_not_private_keys() {
        let dir = ssh_dir_with(&[("id_test", FAKE_KEY), ("config.bak", "Host x\n")]);

        let names: Vec<String> = list_ssh_keys(dir.path())
            .unwrap()
            .into_iter()
            .map(|k| k.name)
            .collect();

        assert_eq!(names, vec!["id_test"]);
    }

    #[test]
    fn find_key_requires_exact_name() {
        let dir = ssh_dir_with(&[("id_ed25519", FAKE_KEY)]);

        assert!(find_key(dir.path(), "id_ed25519").is_ok());
        assert!(matches!(
            find_key(dir.path(), "25519"),
            Err(MySshError::KeyNotFound { .. })
        ));
    }

    #[test]
    fn find_key_accepts_explicit_path() {
        let dir = ssh_dir_with(&[("id_elsewhere", FAKE_KEY)]);
        let empty = TempDir::new().unwrap();
        let path = dir.path().join("id_elsewhere");

        let key = find_key(empty.path(), path.to_str().unwrap()).unwrap();

        assert_eq!(key.name, "id_elsewhere");
    }

    #[test]
    fn detail_hides_private_key_unless_requested() {
        let dir = ssh_dir_with(&[("id_test", FAKE_KEY)]);
        let key = find_key(dir.path(), "id_test").unwrap();

        assert!(!format_key_detail(&key, false).contains("PRIVATE KEY"));
        assert!(format_key_detail(&key, true).contains("PRIVATE KEY"));
    }

    #[cfg(unix)]
    #[test]
    fn ensure_private_dir_creates_owner_only_dir() {
        use std::os::unix::fs::PermissionsExt;

        let parent = TempDir::new().unwrap();
        let dir = parent.path().join("nested/.ssh");

        ensure_private_dir(&dir).unwrap();

        let mode = fs::metadata(&dir).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
    }
}
