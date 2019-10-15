use std::path::Path;
extern crate dirs;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate serde_yaml;
#[macro_use]
extern crate failure;
use failure::Error;

mod errors;
use errors::{other_error, ConfigError};
mod deserializers;
use deserializers::from_base64;
use std::collections::HashMap;
mod utils;

use openssl::{pkcs12::Pkcs12, pkey::PKey, x509::X509};
use std::process::Command;

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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ExecCredentialSpec {}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ExecCredential {
    pub kind: Option<String>,

    pub api_version: Option<String>,
    pub spec: Option<ExecCredentialSpec>,
    pub status: Option<ExecCredentialStatus>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ExecCredentialStatus {
    pub expiration_timestamp: Option<String>,
    pub token: Option<String>,
    pub client_certificate_data: Option<String>,
    pub client_key_data: Option<String>,
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

impl ExecConfig {
    pub fn auth_exec(&self) -> Result<ExecCredential, ConfigError> {
        let mut cmd = Command::new(&self.command);
        if let Some(args) = &self.args {
            cmd.args(args);
        };
        // @TODO: fixme 
        if let Some(env) = &self.env {
            cmd.envs(
                env.into_iter()
                    .map(|ref kvpair| (kvpair.name.clone(), kvpair.value.clone()))
                    .collect::<HashMap<String, String>>(),
            );
        }
        let out = cmd
            .output()
            .map_err(|e| ConfigError::ExecError(e.to_string()))?;
        if !out.status.success() {
            let error = format!("command `{:?}` failed: {:?}", cmd, out);
            dbg!(&error);
            return Err(ConfigError::ExecError(error));
        }
        let result: Result<ExecCredential, ConfigError> =
            serde_json::from_slice(&out.stdout).map_err(|e| ConfigError::ExecError(e.to_string()));
        result
    }
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
    #[serde(rename = "exec")]
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
    #[serde(
        default,
        deserialize_with = "deserializers::auth_info_de",
        rename = "users"
    )]
    auth_infos: HashMap<String, AuthInfo>,
    #[serde(deserialize_with = "deserializers::context_de")]
    contexts: HashMap<String, Context>,
    current_context: String,
    extensions: Extensions,
}

use std::collections::hash_map::Iter;

impl Config {
    pub fn load_from_file<T: AsRef<Path>>(name: T) -> Result<Config, Error> {
        let f = std::fs::File::open(name)?;
        Ok(serde_yaml::from_reader(f)?)
    }

    pub fn load_from_data(data: &[u8]) -> Result<Config, Error> {
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

    pub fn merge_with(mut self, config: Config) -> Result<Config, Error> {
        self.clusters = Config::merge_hashmap(self.clusters, config.clusters);
        self.auth_infos = Config::merge_hashmap(self.auth_infos, config.auth_infos);
        self.contexts = Config::merge_hashmap(self.contexts, config.contexts);
        Ok(self)
    }

    pub fn load<T: AsRef<Path>>(filename: Option<T>) -> Result<Config, Error> {
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
                            loaded_config
                                .take()
                                .unwrap()
                                .merge_with(Config::load_from_file(path)?)?,
                        );
                    }
                }
                loaded_config.ok_or(
                    ConfigError::Other {
                        cause: "Something bad happened".to_owned(),
                    }
                    .into(),
                )
            } else if let Some(homedir) = dirs::home_dir() {
                let kubeconfig = std::path::Path::new(&homedir).join(".kube").join("config");
                if kubeconfig.exists() {
                    Config::load_from_file(kubeconfig)
                } else {
                    Err(ConfigError::Other {
                        cause: "Cannot find config to load".to_owned(),
                    }
                    .into())
                }
            } else {
                Err(ConfigError::Other {
                    cause: "Cannot find config to load".to_owned(),
                }
                .into())
            }
        }
    }

    pub fn get_current(&self) -> Option<&Cluster> {
        if let Some(ref context) = self.contexts.get(&self.current_context) {
            self.clusters.get(&context.cluster)
        } else {
            None
        }
    }

    pub fn load_certificate_authority(&self) -> Result<Vec<u8>, ConfigError> {
        if let Some(cluster) = self.get_current() {
            if let Some(ca_file) = &cluster.certificate_authority {
                return utils::load_ca_from_file(ca_file);
            } else if let Some(ca_data) = &cluster.certificate_authority_data {
                return Ok(ca_data.to_vec());
            } else {
                return Err(other_error("No ca data or file found"));
            }
        } else {
            return Err(other_error("No ca data or file found"));
        }
    }

    pub fn ca_bundle(&self) -> Result<Vec<X509>, ConfigError> {
        let bundle = self
            .load_certificate_authority()
            .map_err(|e| ConfigError::SSLError(e.to_string()))?;
        X509::stack_from_pem(&bundle).map_err(|e| ConfigError::SSLError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::path::PathBuf;

    fn load_from_fixture(fixture_name: &str) -> Result<Config, Error> {
        let mut manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        manifest_dir.push("fixtures");
        manifest_dir.push(fixture_name);
        Config::load(Some(manifest_dir))
    }

    #[test]
    fn should_load_ca_from_file() {
        let c = load_from_fixture("ca-from-file.yaml").unwrap();
        let mut manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        manifest_dir.push("fixtures");
        // Change $HOME for given test to point to fixture directory
        env::set_var("HOME", manifest_dir);
        println!("user profile var: {:?}", env::var("HOME").unwrap());
        assert!(
            c.load_certificate_authority().is_ok(),
            format!("{:?}", c.load_certificate_authority().err())
        );
    }

    #[test]
    fn should_load_ca_from_data() {
        let c = load_from_fixture("ca-from-data.yaml").unwrap();
        assert!(c.ca_bundle().is_ok(), format!("{:?}", c.ca_bundle().err()));
        for cert in c.ca_bundle().unwrap() {
            let _ = cert
                .subject_name()
                .entries()
                .map(|el| println!("subject_name: {:?}", el.data().as_utf8().unwrap()))
                .collect::<Vec<()>>();
        }
    }

    #[test]
    fn should_try_to_load_default() {
        let config = Config::load(None::<&Path>);
        match config {
            Ok(config) => println!("config: {:?}", config),
            Err(e) => {
                eprintln!("error: {:?}", e);
            }
        };
    }

    #[test]
    fn should_load_multiple_cluster_config() {
        let mut manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        manifest_dir.push("fixtures/multiple-clusters.yaml");
        let c = Config::load(Some(manifest_dir));
        assert!(c.is_ok());
        let c = c.unwrap();
        assert!(c.clusters.len() == 2);
        assert!(c.contexts.len() == 3);
        assert!(c.current_context == "");
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
            Ok(config) => {} //println!("config: {:?}", config),
            Err(e) => {
                eprintln!("error: {:?}", e);
            }
        };
        assert!(Config::load_from_data(data.as_bytes()).is_ok());
    }
}
