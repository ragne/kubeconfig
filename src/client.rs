use crate::errors::{ConfigError, Result};
use crate::{Config, Context};
use failure::format_err;
use reqwest::{header, Certificate, Client, ClientBuilder, Identity};

pub struct KubeClient {
    pub namespace: String,
    client: Client,
    config: Option<Config>,
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
                        // last resort only if configs ask for it, and no client certs
                        if let Some(true) = &current_view.cluster.insecure_skip_tls_verify {
                            client_builder = client_builder.danger_accept_invalid_certs(true);
                        }
                    }
                }
            }
            let mut headers = header::HeaderMap::new();
            // @TODO: Populate tokens from user\auth-info

            self.client = client_builder.default_headers(headers).build()?;
            Ok(())
        }
    }

    #[must_use]
    pub fn build(mut self) -> Result<KubeClient> {
        self.init_client()?;
        Ok(KubeClient {
            client: self.client,
            config: self.config,
            namespace: self.namespace,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{get_fixtures_dir, load_from_fixture};
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
}
