use crate::errors::{other_error, ConfigError};
use base64::decode;
use dirs::home_dir;
use std::convert::TryInto;
use std::env;
use std::fs::{metadata, File};
use std::io::Read;
use std::path::{Path, PathBuf};

const KUBECONFIG: &str = "KUBECONFIG";

#[inline(always)]
fn default_kube_dir() -> Option<PathBuf> {
    home_dir().map(|h| h.join(".kube"))
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
    println!("filename is: {:?}", &filename);
    let mut file = File::open(filename.clone()).map_err(|e| ConfigError::IOError { inner: e })?;
    let mut buf = Vec::with_capacity(
        metadata(filename)?
            .len()
            .try_into()
            .expect("Cannot convert file len to u64"),
    );
    file.read_to_end(&mut buf)?;

    Ok(buf.to_vec())
    // Ok(base64::decode(&buf)
        // .map_err(|e| other_error(format!("Cannot decode base64 data. caused by: {}", e)))?)
}


