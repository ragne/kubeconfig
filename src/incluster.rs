use crate::errors::{ConfigError, Result};
use crate::utils;
use openssl::x509::X509;

// https://kubernetes.io/docs/tasks/administer-cluster/access-cluster-api/#accessing-the-api-from-a-pod
pub const K8S_API: &str = "kubernetes.default.svc";
const K8S_TOKENFILE: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";
const K8S_CERTFILE: &str = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";
const K8S_DEFAULT_NS: &str = "/var/run/secrets/kubernetes.io/serviceaccount/namespace";

fn load_ca() -> Result<X509> {
    X509::from_pem(&utils::load_ca_from_file(K8S_CERTFILE)?).map_err(|e| e.into())
}

pub fn load_default_ns() -> Result<String> {
    utils::load_file(K8S_DEFAULT_NS)
        .and_then(|r| String::from_utf8(r).
            map_err(|e| ConfigError::LoadingError(e.to_string()))
        )
}

pub fn load_token() -> Result<String> {
    utils::load_file(K8S_TOKENFILE)
    .and_then(|r| String::from_utf8(r).
        map_err(|e| ConfigError::LoadingError(e.to_string()))
    )
}