use std::path::Path;
#[macro_use]
extern crate serde_derive;
extern crate serde_yaml;
#[macro_use]
extern crate failure;
use failure::Error;

mod errors;
use errors::ConfigError;
mod deserializers;
use deserializers::from_base64;
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct Preferences {
    colors: Option<bool>,
    extensions: Extensions,
}


#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct Cluster {
    server: String,
    insecure_skip_tls_verify: Option<bool>,
    certificate_authority: Option<String>,
    #[serde(default, deserialize_with = "from_base64")]
    certificate_authority_data: Option<Vec<u8>>,
    extensions: Extensions,
}


#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct Context {
    cluster: String,
    auth_info: Option<String>, // may become &AuthInfo but everything will be lifetime-tied
    namespace: Option<String>,
    extensions: Extensions,
}


#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct AuthProviderConfig {
    name: String,
    config: Option<HashMap<String, String>>,
}

// type ExecConfig struct {
//     // Command to execute.
//     Command string `json:"command"`
//     // Arguments to pass to the command when executing it.
//     // +optional
//     Args []string `json:"args"`
//     // Env defines additional environment variables to expose to the process. These
//     // are unioned with the host's environment, as well as variables client-go uses
//     // to pass argument to the plugin.
//     // +optional
//     Env []ExecEnvVar `json:"env"`

//     // Preferred input version of the ExecInfo. The returned ExecCredentials MUST use
//     // the same encoding version as the input.
//     APIVersion string `json:"apiVersion,omitempty"`
// }

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct KeyValuePair {
    name: String,
    value: String,
}

type ExecEnvVars = Vec<KeyValuePair>;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct ExecConfig {
    command: String,
    args: Option<Vec<String>>,
    env: Option<ExecEnvVars>,
    api_version: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct AuthInfo {
    client_certificate: Option<String>,
    #[serde(default, deserialize_with = "from_base64")]
    client_certificate_data: Option<Vec<u8>>,
    client_key: Option<String>,
    client_key_data: Option<String>,
    token: Option<String>,
    token_file: Option<String>, // maybe Path
    #[serde(rename = "act-as")]
    impersonate: Option<String>,
    #[serde(rename = "act-as-groups")]
    impersonate_groups: Option<Vec<String>>,
    #[serde(rename = "act-as-user-extra")]
    impersonate_user_extra: Option<HashMap<String, String>>,
    username: Option<String>,
    password: Option<String>,
    auth_provider: Option<AuthProviderConfig>,
    #[serde(rename="exec")]
    exec_config: Option<ExecConfig>,
    extensions: Extensions,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct Extension;

type Extensions = Option<HashMap<String, Extension>>;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct Config {
    kind: Option<String>,
    api_version: Option<String>,
    preferences: Preferences,
    #[serde(default, deserialize_with = "deserializers::cluster_de")]
    clusters: HashMap<String, Cluster>,
    #[serde(default, deserialize_with = "deserializers::auth_info_de", rename="users")]
    auth_infos: HashMap<String, AuthInfo>,
    #[serde(deserialize_with = "deserializers::context_de")]
    contexts: HashMap<String, Context>,
    current_context: String,
    extensions: Extensions,
}

use std::collections::hash_map::Iter;

impl Config {
    fn load_from_file<T: AsRef<Path>>(name: T) -> Result<Config, Error> {
        let f = std::fs::File::open(name)?;
        Ok(serde_yaml::from_reader(f)?)
    }

    fn load_from_data(data: &[u8]) -> Result<Config, Error> {
        Ok(serde_yaml::from_slice(data)?)
    }

    fn merge_hashmap<T>(mut a: HashMap<String, T>, b: HashMap<String, T>) -> HashMap<String, T> {
        for (k, v) in b.into_iter() {
            if a.get(&k).is_none() {
                a.insert(k, v);
            }
        }
        a
    }

    fn merge_with(mut self, config: Config) -> Result<Config, Error> {
        self.clusters = Config::merge_hashmap(self.clusters, config.clusters);
        self.auth_infos = Config::merge_hashmap(self.auth_infos, config.auth_infos);
        self.contexts = Config::merge_hashmap(self.contexts, config.contexts);
        Ok(self)
    }

    fn load<T: AsRef<Path>>(filename: Option<T>) -> Result<Config, Error> {
        if let Some(filename) = filename {
            Config::load_from_file(filename)
        } else {
            // load KUBECONFIG here
            if let Ok(ref kubeconfig) = std::env::var("KUBECONFIG") {
                let mut loaded_config = None;
                for path in std::env::split_paths(kubeconfig) {
                    if loaded_config.is_none() {
                    loaded_config = Some(Config::load_from_file(path)?);
                    } else {
                        loaded_config = Some(
                            loaded_config.take().unwrap().merge_with(Config::load_from_file(path)?)?);
                    }
                }
                loaded_config.ok_or(ConfigError::Other{cause:"Something bad happened".to_owned()}.into())
            } else if let Some(homedir) = std::env::home_dir() {
                let kubeconfig = std::path::Path::new(&homedir).join(".kube").join("config");
                if kubeconfig.exists() {
                    Config::load_from_file(kubeconfig)
                } else {
                    Err(ConfigError::Other{cause:"Cannot find config to load".to_owned()}.into())
                }
            } else {
                    Err(ConfigError::Other{cause:"Cannot find config to load".to_owned()}.into())
                }

            
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_works() {
        let config = Config::load(None::<&Path>);
        match config {
            Ok(config) => println!("config: {:?}", config),
            Err(e) => {
                eprintln!("error: {:?}", e);
            }
        };
        assert!(Config::load(Some("/home/l/.kube/config")).is_ok());
    }

    #[test]
    fn load_from_text() {
        let data = r###"current-context: federal-context
apiVersion: v1
clusters:
- cluster:
    api-version: v1
    server: http://cow.org:8080
  name: cow-cluster
- cluster:
    certificate-authority: path/to/my/cafile
    server: https://horse.org:4443
  name: horse-cluster
- cluster:
    insecure-skip-tls-verify: true
    server: https://pig.org:443
  name: pig-cluster
contexts:
- context:
    cluster: horse-cluster
    namespace: chisel-ns
    user: green-user
  name: federal-context
- context:
    cluster: pig-cluster
    namespace: saw-ns
    user: black-user
  name: queen-anne-context
kind: Config
preferences:
  colors: true
users:
- name: blue-user
  user:
    token: blue-token
- name: green-user
  user:
    client-certificate: path/to/my/client/cert
    client-key: path/to/my/client/key"###;
        match Config::load_from_data(data.as_bytes()) {
            Ok(config) => {}//println!("config: {:?}", config),
            Err(e) => {
                eprintln!("error: {:?}", e);
            }
        };
        assert!(Config::load_from_data(data.as_bytes()).is_ok());
    }
}
