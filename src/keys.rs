use crate::error::{MySshError, Result};
use serde::Serialize;
use ssh_key::{Algorithm, HashAlg, PrivateKey, PublicKey};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

const EXCLUDED_FILES: &[&str] = &[
    "known_hosts",
    "known_hosts.old",
    "authorized_keys",
    "config",
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

    if let Ok(env_dir) = std::env::var("MYSSH_DIR") {
        return Ok(PathBuf::from(env_dir));
    }

    let home = std::env::var("HOME").map_err(|_| MySshError::HomeNotSet)?;
    Ok(Path::new(&home).join(".ssh"))
}

pub fn should_show_file_name(file_name: &str) -> bool {
    if EXCLUDED_FILES.contains(&file_name) {
        return false;
    }

    !file_name.ends_with(".pub")
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

fn read_public_key_content(pub_path: &Path) -> Option<String> {
    fs::read_to_string(pub_path).ok()
}

fn parse_key_details(private_path: &Path, contents: &str) -> KeyDetails {
    let pub_path = public_key_path(private_path);
    let public_key_path_str = pub_path.exists().then(|| pub_path.display().to_string());

    let public_key_from_file = public_key_path_str
        .as_ref()
        .and_then(|_| read_public_key_content(&pub_path));

    if let Ok(private_key) = PrivateKey::from_openssh(contents.as_bytes()) {
        let fingerprint = private_key.fingerprint(HashAlg::Sha256).to_string();
        let algorithm = algorithm_name(private_key.algorithm());
        let comment = {
            let c = private_key.comment();
            if c.is_empty() {
                None
            } else {
                Some(c.to_string())
            }
        };
        let encrypted = private_key.is_encrypted();
        let public_key = public_key_from_file.or_else(|| {
            private_key
                .public_key()
                .to_openssh()
                .ok()
                .map(|s| s.to_string())
        });

        return KeyDetails {
            algorithm,
            fingerprint,
            comment,
            encrypted,
            public_key,
            public_key_path: public_key_path_str,
        };
    }

    if let Some(public_content) = public_key_from_file.as_deref() {
        if let Ok(public_key) = PublicKey::from_openssh(public_content) {
            let fingerprint = public_key.fingerprint(HashAlg::Sha256).to_string();
            return KeyDetails {
                algorithm: algorithm_name(public_key.algorithm()),
                fingerprint,
                comment: None,
                encrypted: contents.contains("ENCRYPTED"),
                public_key: public_key_from_file,
                public_key_path: public_key_path_str,
            };
        }
    }

    KeyDetails {
        algorithm: "Unknown".to_string(),
        fingerprint: "N/A".to_string(),
        comment: None,
        encrypted: contents.contains("ENCRYPTED"),
        public_key: public_key_from_file,
        public_key_path: public_key_path_str,
    }
}

pub fn inspect_key(path: &Path) -> Result<SshKeyInfo> {
    let contents = fs::read_to_string(path).map_err(|err| MySshError::ReadError {
        path: path.to_path_buf(),
        source: err.to_string(),
    })?;

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
    let entries = fs::read_dir(ssh_dir).map_err(|err| {
        MySshError::General(format!("Unable to list {}: {err}", ssh_dir.display()))
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

pub fn find_key(ssh_dir: &Path, name: &str) -> Result<SshKeyInfo> {
    let keys = list_ssh_keys(ssh_dir)?;
    keys.into_iter()
        .find(|k| k.name == name || k.path.ends_with(name))
        .ok_or_else(|| MySshError::KeyNotFound {
            name: name.to_string(),
        })
}

pub fn format_key_detail(key: &SshKeyInfo) -> String {
    let mut output = String::new();

    output.push_str(&format!("Path: {}\n", key.path));
    output.push_str(&format!("Size: {} bytes\n", key.metadata.size_bytes));

    if let Some(modified) = &key.metadata.modified {
        output.push_str(&format!("Modified: {modified}\n"));
    }

    output.push_str(&format!("Permissions: {}", key.metadata.permissions));
    if !key.metadata.permissions_secure {
        output.push_str(" (WARNING: too permissive)");
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
