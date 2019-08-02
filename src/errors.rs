#[derive(Debug, Fail)]
pub(crate) enum ConfigError {
    #[fail(display = "encountered an IO error: {}", inner)]
    IOError { inner: std::io::Error },
    #[fail(display = "other error: {}", cause)]
    Other { cause: String },
    #[fail(display = "Merge error: {}", cause)]
    FailedMerge { cause: String }
}
