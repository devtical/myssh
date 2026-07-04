use std::fmt;
use std::path::PathBuf;

#[derive(Debug)]
pub enum MySshError {
    HomeNotSet,
    SshDirNotFound { path: PathBuf },
    NoKeysFound { path: PathBuf },
    KeyNotFound { name: String },
    ReadError { path: PathBuf, source: String },
    WriteError { path: PathBuf, source: String },
    ParseError { path: PathBuf, source: String },
    ClipboardError(String),
    CommandError(String),
    General(String),
}

impl fmt::Display for MySshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HomeNotSet => write!(f, "HOME environment variable not set"),
            Self::SshDirNotFound { path } => {
                write!(f, "Unable to access SSH directory: {}", path.display())
            }
            Self::NoKeysFound { path } => write!(f, "No SSH key files found in {}", path.display()),
            Self::KeyNotFound { name } => write!(f, "SSH key not found: {name}"),
            Self::ReadError { path, source } => {
                write!(f, "Unable to read {}: {source}", path.display())
            }
            Self::WriteError { path, source } => {
                write!(f, "Unable to write {}: {source}", path.display())
            }
            Self::ParseError { path, source } => {
                write!(f, "Unable to parse {}: {source}", path.display())
            }
            Self::ClipboardError(msg) => write!(f, "Clipboard error: {msg}"),
            Self::CommandError(msg) => write!(f, "{msg}"),
            Self::General(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for MySshError {}

impl MySshError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::HomeNotSet => 2,
            Self::SshDirNotFound { .. } => 3,
            Self::NoKeysFound { .. } => 4,
            Self::KeyNotFound { .. } => 5,
            Self::ReadError { .. } | Self::ParseError { .. } => 6,
            Self::WriteError { .. }
            | Self::ClipboardError(_)
            | Self::CommandError(_)
            | Self::General(_) => 1,
        }
    }
}

pub type Result<T> = std::result::Result<T, MySshError>;
