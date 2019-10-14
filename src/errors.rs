#[derive(Debug, Fail)]
pub(crate) enum ConfigError {
    #[fail(display = "encountered an IO error: {}", inner)]
    IOError { inner: std::io::Error },
    #[fail(display = "other error: {}", cause)]
    Other { cause: String },
    #[fail(display = "Merge error: {}", cause)]
    FailedMerge { cause: String },
    #[fail(display = "SSL error: {}", 0)]
    SSLError(String)
    
}

pub(crate) fn other_error<P:Into<String>>(cause: P) -> ConfigError {
    ConfigError::Other{cause: cause.into()}
}

impl From<std::io::Error> for ConfigError {
    fn from(e: std::io::Error) -> ConfigError {
        ConfigError::IOError{inner: e}
    }
}