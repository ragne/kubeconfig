use crate::errors::{ConfigError, Result};
use crate::{Config, Context, CurrentView};
use failure::format_err;
use reqwest::{header, Certificate, Client, ClientBuilder, Identity};

pub struct KubeClient {
    pub namespace: String,
    client: Client,
    config: Config,
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

    fn set_auth_headers(current_view: &CurrentView, headers: &mut reqwest::header::HeaderMap<reqwest::header::HeaderValue>) -> Result<()> {
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
                    .map_err(|_| {
                        ConfigError::LoadingError("Invalid bearer token".to_owned())
                    })?,
                );
            }
            (None, (Some(username), Some(password))) => {
                let encoded = base64::encode(&format!("{}:{}", username, password));
                headers.insert(
                    header::AUTHORIZATION,
                    header::HeaderValue::from_str(&format!("Basic {}", encoded)).map_err(
                        |_| {
                            ConfigError::LoadingError(
                                "Cannot encode basic auth credentials".to_owned(),
                            )
                        },
                    )?,
                );
            }
            _ => {}
        };
        Ok(())
    }

    fn init_client(&mut self) -> Result<()> {
        let mut client_builder = Client::builder();
        if self.config.is_none() {
            Err(ConfigError::Unknown(format_err!("No config was found!")))
        } else {
            // @TODO: [tidying] remove all unwraps
            if let Ok(bundle) = self.config.as_mut().unwrap().ca_bundle() {
                for ca in bundle {
                    let cert = Certificate::from_der(&ca.to_der()?)?;
                    client_builder = client_builder.add_root_certificate(cert);
                }
            }
            let current_view = self.config.as_mut().unwrap().get_current_view().unwrap();
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
            // @TODO: Populate tokens from user\auth-info
            KubeClientBuilder::set_auth_headers(&current_view, &mut headers)?;

            self.client = client_builder.default_headers(headers).build()?;
            Ok(())
        }
    }

    #[must_use]
    pub fn build(mut self) -> Result<KubeClient> {
        self.init_client()?;
        // at this point config is not null
        Ok(KubeClient {
            client: self.client,
            config: self.config.unwrap(),
            namespace: self.namespace,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{load_from_fixture};
    use reqwest::Client;

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
        let mut config = load_from_fixture("ca-from-data.yaml").unwrap();
        let mut headers = header::HeaderMap::new();
        let res = KubeClientBuilder::set_auth_headers(&config.get_current_view().unwrap(), &mut headers);
        assert!(res.is_ok(), format!("failed with: {:?}", res.err()));
        assert!(headers.get(reqwest::header::AUTHORIZATION).is_some());
        println!("headers: {:?}", headers);

        let mut config = load_from_fixture("multiple-clusters.yaml").unwrap();
        config.set_current("exp-scratch").expect("expect exp-scratch to exist");
        let mut headers = header::HeaderMap::new();
        let res = KubeClientBuilder::set_auth_headers(&config.get_current_view().unwrap(), &mut headers);
        assert!(res.is_ok(), format!("failed with: {:?}", res.err()));
        assert!(headers.get(reqwest::header::AUTHORIZATION).is_some());
        println!("headers: {:?}", headers);
    }
}
