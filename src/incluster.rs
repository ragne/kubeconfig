use crate::errors::{ConfigError, Result};
use crate::utils;
use openssl::x509::X509;
use std::env::var;
use std::str::FromStr;

// https://kubernetes.io/docs/tasks/administer-cluster/access-cluster-api/#accessing-the-api-from-a-pod
pub const K8S_API: &str = "kubernetes.default.svc";
const K8S_TOKENFILE: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";
const K8S_CERTFILE: &str = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";
const K8S_DEFAULT_NS: &str = "/var/run/secrets/kubernetes.io/serviceaccount/namespace";
const K8S_HOST: &str = "KUBERNETES_SERVICE_HOST";
const K8S_PORT: &str = "KUBERNETES_SERVICE_PORT";

fn load_ca() -> Result<X509> {
    X509::from_pem(&utils::load_ca_from_file(K8S_CERTFILE)?).map_err(|e| e.into())
}

pub fn load_default_ns() -> Result<String> {
    utils::load_file(K8S_DEFAULT_NS)
        .and_then(|r| String::from_utf8(r).map_err(|e| ConfigError::LoadingError(e.to_string())))
}

pub fn load_token() -> Result<String> {
    utils::load_file(K8S_TOKENFILE)
        .and_then(|r| String::from_utf8(r).map_err(|e| ConfigError::LoadingError(e.to_string())))
}

pub fn k8s_server() -> Option<String> {
    var(K8S_HOST)
        .and_then(|host| var(K8S_PORT).and_then(|port| {
            if u16::from_str(&port).is_ok() {
                Ok(format!("https://{}:{}", host, port))
            } else {
                Err(std::env::VarError::NotPresent)
            }
        }))
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env::set_var;
    #[test]
    fn should_get_k8s_server_from_env() {
        set_var(K8S_HOST, "example.com");
        set_var(K8S_PORT, "443");
        assert_eq!(k8s_server(), Some("https://example.com:443".into()));
    }
}
