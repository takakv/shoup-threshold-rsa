use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to {action} {}", path.display())]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("{} is not a valid {kind}", path.display())]
    Der {
        path: PathBuf,
        kind: &'static str,
        #[source]
        source: der::Error,
    },

    #[error("failed to read public key {}", path.display())]
    PublicKey {
        path: PathBuf,
        #[source]
        source: rsa::pkcs8::spki::Error,
    },

    #[error("{}: {reason}", path.display())]
    Malformed { path: PathBuf, reason: &'static str },

    #[error("no shares found in {}", dir.display())]
    NoShares { dir: PathBuf },

    #[error("only {valid}/{provided} shares are usable, below threshold of {threshold}")]
    NotEnoughShares {
        valid: usize,
        provided: usize,
        threshold: u16,
    },

    #[error("RSA modulus is too small for PSS encoding")]
    PssEncoding,

    #[error("could not generate PSS salt")]
    PssSalt,
}

pub type Result<T> = std::result::Result<T, Error>;
