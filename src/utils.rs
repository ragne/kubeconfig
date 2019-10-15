use crate::errors::{other_error, ConfigError};
use dirs::home_dir;
use std::convert::TryInto;
use std::env;
use std::fs::{metadata, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use base64;

const KUBECONFIG: &str = "KUBECONFIG";

#[cfg(not(test))]
#[inline(always)]
fn default_kube_dir() -> Option<PathBuf> {
    home_dir().map(|h| h.join(".kube"))
}

#[doc(hidden)]
#[cfg(test)]
#[inline(always)]
fn default_kube_dir() -> Option<PathBuf> {
    let mut manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir.push("fixtures");
    manifest_dir.push(".kube");
    Some(manifest_dir)
}

pub(crate) fn b64decode(bytes: &[u8]) -> Result<Vec<u8>, ConfigError> {
    base64::decode(bytes).map_err(|e| ConfigError::B64DecodeError(e.to_string()))
}

pub fn default_kube_path() -> Option<PathBuf> {
    default_kube_dir().map(|dir| dir.join("config"))
}

pub(crate) fn find_kubeconfig() -> Result<PathBuf, ConfigError> {
    env::var_os(KUBECONFIG)
        .map(PathBuf::from)
        .or_else(default_kube_path)
        .ok_or_else(|| ConfigError::Other {
            cause: "Cannot find a config!".to_owned(),
        })
}

pub(crate) fn load_ca_from_file<P: AsRef<Path>>(filename: P) -> Result<Vec<u8>, ConfigError> {
    let filename = filename.as_ref();
    let filename = if filename.is_absolute() {
        filename.to_path_buf()
    } else {
        //
        default_kube_dir()
            .and_then(|dir| Some(dir.join(filename)))
            .ok_or_else(|| other_error(format!("Cannot load file {}", filename.display())))?
    };

    let mut file = File::open(filename.clone()).map_err(|e| ConfigError::IOError { inner: e })?;
    let mut buf = Vec::with_capacity(
        metadata(filename)?
            .len()
            .try_into()
            .expect("Cannot convert file len to u64"),
    );
    file.read_to_end(&mut buf)?;

    // Guess files aren't encoded in base64
    Ok(buf.to_vec())
}


