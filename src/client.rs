use reqwest::{header, Certificate, Client, ClientBuilder, Identity};
use crate::{Config, Context};


pub struct KubeClient {
    pub namespace: String,
    client: Client,
    config: Option<Config>
}

impl KubeClient {
    pub fn new(client: Client) -> Self {
        Self::with_namespace(client, "default".to_string())
    }

    pub fn with_namespace(client: Client, namespace: String) -> Self {
        Self {
            client,
            namespace,
            config: None
        }
    }

    pub fn with_config(mut self, config: Config) -> Self {
        self.config = Some(config);
        self
    }

    pub fn with_context(mut self, context_name: &str) -> Self {
        if let Some(mut config) = self.config.as_mut() {
            if config.contexts.get(context_name).is_some() {
                config.current_context = context_name.to_owned()
            }

        }
        self
    }

    pub fn with_cluster(mut self, cluster_name: &str) -> Self {
        if let Some(mut config) = self.config.as_mut() {
            if config.clusters.get(cluster_name).is_some() {
                config.current_context = cluster_name.to_owned()
            }

        }
        self
    }


}

