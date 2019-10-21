use openssl::error::ErrorStack as opensslError;
use serde_yaml;
use reqwest;

pub type Result<T> = std::result::Result<T, ConfigError>;

#[derive(Debug, Fail)]
pub enum ConfigError {
    #[fail(display = "encountered an IO error: {}", _0)]
    IOError(#[cause] std::io::Error),
    #[fail(display = "unknown\\unhandled error: {}", _0)]
    Unknown(failure::Error),
    #[fail(display = "SSL error: {}", _0)]
    SSLError(#[cause] opensslError),
    #[fail(display = "Exec error: {}", _0)]
    ExecError(String),
    #[fail(display = "Decode error: {}", _0)]
    B64DecodeError(#[cause] base64::DecodeError),
    #[fail(display = "Config data is missing: {}", _0)]
    MissingData(String),
    #[fail(display = "Cannot load config: {}", _0)]
    LoadingError(String),
    #[fail(display = "Element doesn't exist: {}", _0)]
    DoesntExist(String),
    #[fail(display = "Failed to deserialize: {}", _0)]
    DeserializationError(#[cause] serde_yaml::Error),
    #[fail(display = "API client underlying error: {}", _0)]
    ClientError(#[cause] reqwest::Error)
}

impl From<opensslError> for ConfigError {
    fn from(e: opensslError) -> ConfigError {
        ConfigError::SSLError(e)
    }
}

impl From<std::io::Error> for ConfigError {
    fn from(e: std::io::Error) -> ConfigError {
        ConfigError::IOError(e)
    }
}

impl From<base64::DecodeError> for ConfigError {
    fn from(e: base64::DecodeError) -> ConfigError {
        ConfigError::B64DecodeError(e)
    }
}

impl From<serde_yaml::Error> for ConfigError {
    fn from(e: serde_yaml::Error) -> ConfigError {
        ConfigError::DeserializationError(e)
    }
}

impl From<reqwest::Error> for ConfigError {
    fn from(e: reqwest::Error) -> ConfigError {
        ConfigError::ClientError(e)
    }
}