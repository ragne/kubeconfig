use crate::errors::{ConfigError, Result};
use crate::incluster::{k8s_server, load_ca, load_default_ns, load_token, K8S_HOST, K8S_PORT, K8S_API};
use crate::{Config, CurrentView};
use failure::format_err;
use reqwest::{header, Certificate, Client, Identity};

#[derive(Debug)]
pub struct KubeClient {
    pub namespace: String,
    pub server_uri: String,
    pub client: Client,
    pub config: Option<Config>,
}

pub struct KubeClientBuilder {
    namespace: String,
    client: Client,
    config: Option<Config>,
}

impl KubeClientBuilder {
    pub fn new(client: Client) -> Self {
        Self::with_namespace(client, "default".to_string())
    }

    pub fn incluster() -> Result<KubeClient> {
        let server = k8s_server().ok_or_else(|| {
            ConfigError::ConstructionError(format!(
                "Cannot load config, {} and {} must be set!",
                K8S_HOST, K8S_PORT
            ))
        }).unwrap_or(K8S_API.into());

        let ca = Certificate::from_der(&load_ca()?.to_der()?)?;
        let token = load_token()?;
        let default_ns = load_default_ns()?;
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            header::HeaderValue::from_str(&format!("Bearer {}", token))
                .map_err(|_| ConfigError::LoadingError("Invalid bearer token".to_owned()))?,
        );

        let client = Client::builder()
            .add_root_certificate(ca)
            .default_headers(headers)
            .build()?;

        Ok(KubeClient {
            client: client,
            config: None,
            server_uri: server,
            namespace: default_ns,
        })
    }

    pub fn with_namespace(client: Client, namespace: String) -> Self {
        Self {
            client,
            namespace,
            config: None,
        }
    }

    pub fn with_config(mut self, config: Config) -> Self {
        self.config = Some(config);
        self
    }

    #[doc(hidden)]
    fn __with_config<F, T>(&mut self, f: F) -> Result<T>
    where
        F: FnOnce(&mut Config) -> Result<T>,
    {
        if let Some(config) = self.config.as_mut() {
            f(config)
        } else {
            Err(ConfigError::DoesntExist(
                "Config hasn't been initialized".to_owned(),
            ))
        }
    }

    pub fn with_context(mut self, context_name: &str) -> Result<Self> {
        self.__with_config(|c| c.set_current(context_name))?;
        Ok(self)
    }

    pub fn with_cluster(mut self, cluster_name: &str) -> Result<Self> {
        self.__with_config(|c| c.set_current_by_cluster(cluster_name))?;
        Ok(self)
    }

    pub fn with_user(mut self, user_name: &str) -> Result<Self> {
        self.__with_config(|c| c.set_current_by_user(user_name))?;
        Ok(self)
    }

    fn set_auth_headers(
        current_view: &CurrentView,
        headers: &mut reqwest::header::HeaderMap<reqwest::header::HeaderValue>,
    ) -> Result<()> {
        let token = match current_view.auth_info {
            None => None,
            Some(ai) => {
                let token = ai.get_client_token().or_else(|_| {
                    // if nothing was found in auth_info, check exec
                    if let Some(ref ec) = ai.exec_config {
                        ec.exec().map(|cred| {
                            let status = cred.status.ok_or_else(|| {
                                ConfigError::MissingData(
                                    "exec did not return \"status\" field".to_owned(),
                                )
                            })?;

                            match status.token {
                                Some(token) => Ok(token.as_bytes().to_vec()),
                                None => Err(ConfigError::MissingData(
                                    "Missing both token and token_file".to_owned(),
                                )),
                            }
                        })?
                    } else {
                        // absence of token is not an error, but we're in result-returning fn,
                        // so until I find a better way, empty vec would be used as None variant
                        Ok(Vec::new())
                    }
                })?;
                if !token.is_empty() {
                    Some(token)
                } else {
                    None
                }
            }
        };
        let (username, password) = match current_view.auth_info {
            None => (None, None),
            Some(ai) => match (&ai.username, &ai.password) {
                (Some(u), Some(p)) => (Some(u.clone()), Some(p.clone())),
                (Some(u), None) => (Some(u.clone()), Some("".to_owned())),
                _ => (None, None), // doesn't make sense to have a password without username
            },
        };
        match (token, (username, password)) {
            (Some(token), (_, _)) => {
                headers.insert(
                    header::AUTHORIZATION,
                    header::HeaderValue::from_str(&format!(
                        "Bearer {}",
                        String::from_utf8_lossy(&token)
                    ))
                    .map_err(|_| ConfigError::LoadingError("Invalid bearer token".to_owned()))?,
                );
            }
            (None, (Some(username), Some(password))) => {
                let encoded = base64::encode(&format!("{}:{}", username, password));
                headers.insert(
                    header::AUTHORIZATION,
                    header::HeaderValue::from_str(&format!("Basic {}", encoded)).map_err(|_| {
                        ConfigError::LoadingError("Cannot encode basic auth credentials".to_owned())
                    })?,
                );
            }
            _ => {}
        };
        Ok(())
    }

    fn init_client(&mut self) -> Result<()> {
        let mut client_builder = Client::builder();
        match &self.config {
            Some(ref config) => {
                if let Ok(bundle) = config.ca_bundle() {
                    for ca in bundle {
                        let cert = Certificate::from_der(&ca.to_der()?)?;
                        client_builder = client_builder.add_root_certificate(cert);
                    }
                }
                let current_view = config.get_current_view().unwrap();
                if let Some(auth_info) = current_view.auth_info {
                    match auth_info.get_pkcs12(" ") {
                        Ok(p12) => {
                            let req_p12 = Identity::from_pkcs12_der(&p12.to_der()?, " ")?;
                            client_builder = client_builder.identity(req_p12);
                        }
                        Err(_) => {
                            // if config explicitly specifies doing so
                            if let Some(true) = &current_view.cluster.insecure_skip_tls_verify {
                                client_builder = client_builder.danger_accept_invalid_certs(true);
                            }
                        }
                    }
                }
                let mut headers = header::HeaderMap::new();
                KubeClientBuilder::set_auth_headers(&current_view, &mut headers)?;

                self.client = client_builder.default_headers(headers).build()?;
                Ok(())
            }
            None => Err(ConfigError::Unknown(format_err!("No config was found!"))),
        }
    }

    #[must_use]
    pub fn build(mut self) -> Result<KubeClient> {
        self.init_client()?;
        // at this point config is not null
        let server_uri = self
            .config
            .as_ref()
            .unwrap()
            .get_current_view()
            .ok_or_else(|| {
                ConfigError::ConstructionError(
                    "Invalid context selected as current-context!".into(),
                )
            })?
            .cluster
            .server
            .clone();

        Ok(KubeClient {
            client: self.client,
            config: self.config,
            namespace: self.namespace,
            server_uri,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::load_from_fixture;
    use reqwest::Client;
    use std::env::{set_var, remove_var};

    #[test]
    fn should_build_client() {
        let config = load_from_fixture("ca-from-file.yaml").unwrap();
        let http_client = Client::new();
        let kube_client = KubeClientBuilder::new(http_client)
            .with_config(config)
            .with_cluster("my-cluster")
            .and_then(|c| c.with_context("my-context"))
            .and_then(|c| c.build());

        assert!(kube_client.is_ok(), format!("{:?}", kube_client.err()));
    }

    #[test]
    fn test_auth_options() {
        let config = load_from_fixture("ca-from-data.yaml").unwrap();
        let mut headers = header::HeaderMap::new();
        let res =
            KubeClientBuilder::set_auth_headers(&config.get_current_view().unwrap(), &mut headers);
        assert!(res.is_ok(), format!("failed with: {:?}", res.err()));
        assert!(headers.get(reqwest::header::AUTHORIZATION).is_some());
        println!("headers: {:?}", headers);

        let mut config = load_from_fixture("multiple-clusters.yaml").unwrap();
        config
            .set_current("exp-scratch")
            .expect("expect exp-scratch to exist");
        let mut headers = header::HeaderMap::new();
        let res =
            KubeClientBuilder::set_auth_headers(&config.get_current_view().unwrap(), &mut headers);
        assert!(res.is_ok(), format!("failed with: {:?}", res.err()));
        assert!(headers.get(reqwest::header::AUTHORIZATION).is_some());
        println!("headers: {:?}", headers);
    }

    #[test]
    fn test_incluster() {
        let kube_client = KubeClientBuilder::incluster();
        assert!(kube_client.is_ok());
        let kube_client = kube_client.unwrap();
        assert_eq!(kube_client.namespace, "default".to_string());
        assert_eq!(kube_client.server_uri, K8S_API);
        assert!(kube_client.config.is_none());
    }

    #[test]
    fn test_incluster_env_vars() {
        set_var(K8S_HOST, "example.com");
        set_var(K8S_PORT, "443");
        let kube_client = KubeClientBuilder::incluster();
        assert!(kube_client.is_ok());
        let kube_client = kube_client.unwrap();
        assert_eq!(kube_client.namespace, "default".to_string());
        assert_eq!(kube_client.server_uri, "https://example.com:443".to_string());
        assert!(kube_client.config.is_none());
        remove_var(K8S_HOST);
        remove_var(K8S_PORT);
    }
}
