use crate::errors::{ConfigError, Result};
use crate::utils;
use openssl::x509::X509;
use std::env::var;
use std::str::FromStr;

// https://kubernetes.io/docs/tasks/administer-cluster/access-cluster-api/#accessing-the-api-from-a-pod
pub const K8S_API: &str = "kubernetes.default.svc";


// This fuckery needs an explanation I guess. 
// That's the "mocking" for static values, if we run under test, we'll use files from fixtures dir
// otherwise all that leaking shouldn't be seen outside and program will use files in /var/run
lazy_static! {
    pub static ref K8S_TOKENFILE: &'static str = if !cfg!(test) {
        "/var/run/secrets/kubernetes.io/serviceaccount/token"
    } else {
        Box::leak(
            format!("{}{}", env!("CARGO_MANIFEST_DIR"), "/fixtures/incluster/token").into_boxed_str(),
        )
    };
    pub static ref K8S_CERTFILE: &'static str = if !cfg!(test) {
        "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
    } else {
        Box::leak(
            format!("{}{}", env!("CARGO_MANIFEST_DIR"), "/fixtures/.kube/ca.crt").into_boxed_str(),
        )
    };
    pub static ref K8S_DEFAULT_NS: &'static str = if !cfg!(test) {
        "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
    } else {
        Box::leak(
            format!(
                "{}{}",
                env!("CARGO_MANIFEST_DIR"),
                "/fixtures/incluster/namespace"
            )
            .into_boxed_str(),
        )
    };
}
pub(crate) const K8S_HOST: &str = "KUBERNETES_SERVICE_HOST";
pub(crate) const K8S_PORT: &str = "KUBERNETES_SERVICE_PORT";

pub fn load_ca() -> Result<X509> {
    X509::from_pem(&utils::load_ca_from_file(*K8S_CERTFILE)?).map_err(|e| e.into())
}

pub fn load_default_ns() -> Result<String> {
    utils::load_file(*K8S_DEFAULT_NS)
        .and_then(|r| String::from_utf8(r).map_err(|e| ConfigError::LoadingError(e.to_string())))
}

pub fn load_token() -> Result<String> {
    utils::load_file(*K8S_TOKENFILE)
        .and_then(|r| String::from_utf8(r).map_err(|e| ConfigError::LoadingError(e.to_string())))
}

pub fn k8s_server() -> Option<String> {
    var(K8S_HOST)
        .and_then(|host| {
            var(K8S_PORT).and_then(|port| {
                if u16::from_str(&port).is_ok() {
                    Ok(format!("https://{}:{}", host, port))
                } else {
                    Err(std::env::VarError::NotPresent)
                }
            })
        })
        .ok()
}

