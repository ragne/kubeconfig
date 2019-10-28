#![warn(clippy::all)]
use std::path::Path;
extern crate dirs;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate serde_yaml;
#[macro_use]
extern crate failure;

mod errors;
use errors::ConfigError;
mod deserializers;
use deserializers::from_base64;
use std::collections::HashMap;
pub mod client;
mod incluster;
mod utils;

use errors::Result;
use openssl::{pkcs12::Pkcs12, pkey::PKey, x509::X509};
use std::process::Command;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Preferences {
    pub colors: Option<bool>,
    pub extensions: Extensions,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Cluster {
    pub server: String,
    pub insecure_skip_tls_verify: Option<bool>,
    pub certificate_authority: Option<String>,
    #[serde(default, deserialize_with = "from_base64")]
    pub certificate_authority_data: Option<Vec<u8>>,
    pub extensions: Extensions,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Context {
    pub cluster: String,
    #[serde(rename = "user")]
    pub auth_info: Option<String>, // may become &AuthInfo but everything will be lifetime-tied
    pub namespace: Option<String>,
    pub extensions: Extensions,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AuthProviderConfig {
    pub name: String,
    pub config: Option<HashMap<String, String>>,
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

pub type ExecEnvVars = HashMap<String, String>;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ExecConfig {
    pub command: String,
    pub args: Option<Vec<String>>,
    #[serde(default, deserialize_with = "deserializers::value")]
    pub env: ExecEnvVars,
    pub api_version: Option<String>,
}

impl ExecConfig {
    #[cfg(test)]
    pub fn exec(&self) -> Result<ExecCredential> {
        use std::path::PathBuf;
        let mut exe = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        exe.push("fixtures");

        if cfg!(target_os = "windows") {
            exe.push("mock-aws.ps1");
        } else {
            exe.push("mock-aws.sh");
        }
        let mut args = if self.args.is_some() {
            self.args.clone().unwrap()
        } else {
            Vec::new()
        };
        args.insert(0, exe.to_string_lossy().to_string());
        let command;
        if cfg!(target_os = "windows") {
            command = "powershell".to_owned();
        } else {
            command = "bash".to_owned();
        }
        self._real_exec(&command, &args)
    }

    // Common functionality shared by test and non-test code. At least this implementation will be tested
    // I guess that's acceptable trade-off
    #[doc(hidden)]
    fn _real_exec(&self, command: &str, args: &Vec<String>) -> Result<ExecCredential> {
        let mut cmd = Command::new(command);
        cmd.args(args);

        if !&self.env.is_empty() {
            cmd.envs(&self.env);
        }
        let out = cmd
            .output()
            .map_err(|e| ConfigError::ExecError(e.to_string()))?;
        if !out.status.success() {
            let error = format!("command `{:?}` failed: {:?}", cmd, out);
            dbg!(&error);
            return Err(ConfigError::ExecError(error));
        }
        serde_json::from_slice(&out.stdout).map_err(|e| {
            ConfigError::ExecError(format!("Unable to deserialize json: {}", e.to_string()))
        })
    }

    #[cfg(not(test))]
    pub fn exec(&self) -> Result<ExecCredential> {
        let mut args: Vec<String> = Vec::new();
        if let Some(_args) = &self.args {
            args = _args.clone();
        };
        self._real_exec(&self.command, &args)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AuthInfo {
    pub client_certificate: Option<String>,
    #[serde(default, deserialize_with = "from_base64")]
    pub client_certificate_data: Option<Vec<u8>>,
    pub client_key: Option<String>,
    pub client_key_data: Option<String>,
    pub token: Option<String>,
    pub token_file: Option<String>, // maybe Path
    #[serde(rename = "act-as")]
    pub impersonate: Option<String>,
    #[serde(rename = "act-as-groups")]
    pub impersonate_groups: Option<Vec<String>>,
    #[serde(rename = "act-as-user-extra")]
    pub impersonate_user_extra: Option<HashMap<String, String>>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub auth_provider: Option<AuthProviderConfig>,
    #[serde(rename = "exec")]
    pub exec_config: Option<ExecConfig>,
    pub extensions: Extensions,
}

impl AuthInfo {
    pub fn get_client_certificate(&self) -> Result<Vec<u8>> {
        if let Some(cert_data) = &self.client_certificate_data {
            utils::b64decode(&cert_data)
        } else if let Some(cert_file) = &self.client_certificate {
            utils::load_ca_from_file(cert_file)
        } else {
            Err(ConfigError::MissingData(
                "Missing both client_certificate_data and 
            client_certificate"
                    .to_owned(),
            ))
        }
    }

    pub fn get_client_token(&self) -> Result<Vec<u8>> {
        if let Some(token) = &self.token {
            Ok(token.as_bytes().to_vec())
        } else if let Some(ref token_file) = &self.token_file {
            utils::load_file(token_file)
        } else {
            Err(ConfigError::MissingData(
                "Missing both token and token_file".to_owned(),
            ))
        }
    }

    pub fn get_client_key(&self) -> Result<Vec<u8>> {
        if let Some(key_data) = &self.client_key_data {
            utils::b64decode(key_data.as_bytes())
        } else if let Some(key_file) = &self.client_key {
            utils::load_ca_from_file(key_file)
        } else {
            Err(ConfigError::MissingData(
                "Missing both client_key_data and client_key".to_owned(),
            ))
        }
    }

    pub fn get_pkcs12(&self, password: &str) -> Result<Pkcs12> {
        let client_cert = &self.get_client_certificate()?;
        let client_key = &self.get_client_key()?;
        let x509 = X509::from_pem(&client_cert)?;
        let pkey = PKey::private_key_from_pem(&client_key)?;
        Ok(Pkcs12::builder().build(password, "kubeconfig", &pkey, &x509)?)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Extension;

pub type Extensions = Option<HashMap<String, Extension>>;

#[derive(Debug)]
pub struct CurrentView<'a> {
    cluster: &'a Cluster,
    context: &'a Context,
    auth_info: Option<&'a AuthInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Config {
    pub kind: Option<String>,
    pub api_version: Option<String>,
    pub preferences: Preferences,
    #[serde(default, deserialize_with = "deserializers::cluster_de")]
    pub clusters: HashMap<String, Cluster>,
    #[serde(
        default,
        deserialize_with = "deserializers::auth_info_de",
        rename = "users"
    )]
    pub auth_infos: HashMap<String, AuthInfo>,
    #[serde(deserialize_with = "deserializers::context_de")]
    pub contexts: HashMap<String, Context>,
    pub current_context: String,
    pub extensions: Extensions,
}

impl Config {
    pub fn default() -> Result<Config> {
        Config::load(None::<&Path>)
    }

    pub fn load_from_file<T: AsRef<Path>>(name: T) -> Result<Config> {
        let f = std::fs::File::open(name)?;
        Ok(serde_yaml::from_reader(f)?)
    }

    pub fn load_from_data(data: &[u8]) -> Result<Config> {
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

    pub fn merge_with(mut self, config: Config) -> Config {
        self.clusters = Config::merge_hashmap(self.clusters, config.clusters);
        self.auth_infos = Config::merge_hashmap(self.auth_infos, config.auth_infos);
        self.contexts = Config::merge_hashmap(self.contexts, config.contexts);
        self
    }

    pub fn load<T: AsRef<Path>>(filename: Option<T>) -> Result<Config> {
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
                                .merge_with(Config::load_from_file(path)?),
                        );
                    }
                }
                loaded_config
                    .ok_or_else(|| ConfigError::LoadingError("Cannot load config".to_owned()))
            } else if let Ok(kubeconfig) = utils::find_kubeconfig() {
                if kubeconfig.exists() {
                    Config::load_from_file(kubeconfig)
                } else {
                    Err(ConfigError::LoadingError(
                        "Cannot load config: cannot find kubeconfig to load".to_owned(),
                    ))
                }
            } else {
                Err(ConfigError::LoadingError(
                    "Cannot load config: cannot find kubeconfig to load".to_owned(),
                ))
            }
        }
    }

    pub fn get_current(&self) -> Option<&Cluster> {
        if let Some(context) = self.contexts.get(&self.current_context) {
            self.clusters.get(&context.cluster)
        } else {
            None
        }
    }

    pub fn get_view(&self, context_name: &str) -> Option<CurrentView> {
        if let Some(context) = self.contexts.get(context_name) {
            let auth_info = if let Some(auth_info) = context.auth_info.as_ref() {
                self.auth_infos.get(auth_info)
            } else {
                None
            };
            let cluster = self.get_current();
            let cv = CurrentView {
                cluster: cluster?,
                context,
                auth_info,
            };
            Some(cv)
        } else {
            None
        }
    }

    pub fn get_current_view(&self) -> Option<CurrentView> {
        self.get_view(&self.current_context)
    }

    pub fn set_current(&mut self, context_name: &str) -> Result<()> {
        if let Some(_context) = self.contexts.get(context_name) {
            self.current_context = context_name.to_owned();
            Ok(())
        } else {
            Err(ConfigError::DoesntExist(format!(
                "Context with name {} doesn't exist",
                context_name
            )))
        }
    }

    pub fn set_current_by_cluster(&mut self, cluster_name: &str) -> Result<()> {
        if let Some((k, _)) = self
            .contexts
            .iter()
            .find(|(_, v)| v.cluster == cluster_name)
        {
            self.current_context = k.to_owned();
            Ok(())
        } else {
            Err(ConfigError::DoesntExist(format!(
                "Cluster with name {} doesn't exist",
                cluster_name
            )))
        }
    }

    /// Sets current context to one that matches `user` field and has an existing entry in `users` section
    pub fn set_current_by_user(&mut self, user_name: &str) -> Result<()> {
        if self.auth_infos.contains_key(user_name) {
            if let Some(context) = self.contexts.iter().find(|(_, v)| {
                if let Some(ref username) = v.auth_info {
                    username == user_name
                } else {
                    false
                }
            }) {
                self.current_context = context.0.to_owned();
                Ok(())
            } else {
                Err(ConfigError::DoesntExist(format!(
                    "Cluster with name {} doesn't exist",
                    user_name
                )))
            }
        } else {
            Err(ConfigError::DoesntExist(format!(
                "Cluster with name {} doesn't exist",
                user_name
            )))
        }
    }

    pub fn load_certificate_authority(&self) -> Result<Vec<u8>> {
        if let Some(cluster) = self.get_current() {
            if let Some(ca_file) = &cluster.certificate_authority {
                utils::load_ca_from_file(ca_file)
            } else if let Some(ca_data) = &cluster.certificate_authority_data {
                Ok(ca_data.to_vec())
            } else {
                Err(ConfigError::MissingData(
                    "No CA data nor file found".to_owned(),
                ))
            }
        } else {
            Err(ConfigError::DoesntExist(
                "No current cluster was found".to_owned(),
            ))
        }
    }

    pub fn ca_bundle(&self) -> Result<Vec<X509>> {
        let bundle = self.load_certificate_authority()?;
        X509::stack_from_pem(&bundle).map_err(|e| e.into())
    }
}

pub struct ConfigBuilder(Config);

impl ConfigBuilder {
    pub fn new() -> Result<Self> {
        Ok(Self(Config::load(None::<&Path>)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::path::PathBuf;

    pub(crate) fn get_fixtures_dir() -> PathBuf {
        let mut manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        manifest_dir.push("fixtures");
        manifest_dir
    }

    pub(crate) fn load_from_fixture(fixture_name: &str) -> Result<Config> {
        let mut manifest_dir = get_fixtures_dir();
        manifest_dir.push(fixture_name);
        Config::load(Some(manifest_dir))
    }

    #[test]
    fn should_get_pkcs12() {
        let c = load_from_fixture("ca-from-file.yaml").unwrap();
        let res = c.auth_infos.get("green-user").unwrap().get_pkcs12("");
        assert!(
            res.is_ok(),
            format!("get_pkcs12 failed with: {:?}", res.err())
        );
        // typical openssl gymnastics
        res.ok()
            .unwrap()
            .parse("")
            .unwrap()
            .cert
            .subject_name()
            .entries()
            .map(|el| {
                let data = el.data().as_utf8();
                assert!(
                    data.is_ok(),
                    "Certificate subject is not okay/doesn't contain valid utf8"
                );
            })
            .for_each(drop);
    }

    #[test]
    fn should_exec_command() {
        let mut c = load_from_fixture("ca-from-data.yaml").unwrap();
        c.auth_infos
            .get_mut(&c.current_context)
            .and_then(|auth_info| {
                let ec = auth_info.exec_config.take().unwrap();
                let res = ec.exec();
                assert!(
                    res.is_ok(),
                    format!("Exec config failed with: {:?}", res.err())
                );
                println!("{:?}", res.unwrap());
                Some(())
            })
            .unwrap()
    }

    #[test]
    fn should_set_current() {
        let mut c = load_from_fixture("ca-from-data.yaml").unwrap();
        assert!(c.set_current("cluster2").is_ok());
        assert!(c.current_context == "cluster2");
    }

    #[test]
    fn should_set_current_by_user() {
        let mut c = load_from_fixture("ca-from-data.yaml").unwrap();
        assert!(c.set_current_by_user("cluster2").is_ok());
        assert!(c.current_context == "cluster2");
    }

    #[test]
    fn should_set_current_by_cluster() {
        let mut c = load_from_fixture("ca-from-data.yaml").unwrap();
        assert!(c.set_current_by_cluster("cluster2").is_ok());
        assert!(c.current_context == "cluster2");
    }

    #[test]
    fn should_fail_set_non_existing_values() {
        let mut c = load_from_fixture("ca-from-data.yaml").unwrap();
        assert!(c.set_current_by_cluster("non-existing").is_err());
        assert!(c.set_current_by_user("non-existing").is_err());
        assert!(c.set_current("non-existing").is_err());
        assert!(c.current_context == "cluster1");
    }

    #[test]
    fn should_load_ca_from_file() {
        let c = load_from_fixture("ca-from-file.yaml").unwrap();
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
        let config = Config::default();
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
            Ok(_config) => {}
            Err(e) => {
                eprintln!("error: {:?}", e);
            }
        };
        assert!(Config::load_from_data(data.as_bytes()).is_ok());
    }
}
