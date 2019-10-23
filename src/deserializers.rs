use base64;
use serde::{Deserialize, Deserializer};
use std::collections::HashMap;

pub fn from_base64<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    Ok(Some(
        String::deserialize(deserializer)
            .and_then(|string| base64::decode(&string).map_err(Error::custom))
            .map_err(Error::custom)?,
    ))
}

///
/// Macro for generating deserializers
/// Basic idea adapted from https://github.com/serde-rs/serde/issues/1369
/// This is done to deserialize k8s' sequence of (key,value) into rust hashmap
macro_rules! deserializer_for {
    ($type: ident, $fn_name: ident) => {
        pub fn $fn_name<'de, T, D>(deserializer: D) -> Result<HashMap<String, T>, D::Error>
        where
            D: Deserializer<'de>,
            T: Deserialize<'de>,
        {
            #[derive(Deserialize, Debug)]
            struct Wrapper<T> {
                name: String,
                $type: T,
            }
            let mut _v = Vec::<Wrapper<T>>::deserialize(deserializer)?;
            let map: HashMap<String, T> = _v.drain(..).map(|el| (el.name, el.$type)).collect();
            Ok(map)
        }
    };
}

deserializer_for!(cluster, cluster_de);
deserializer_for!(context, context_de);
deserializer_for!(user, auth_info_de);
// This is a hack for macro reuse to generate auto Deserialize for
// struct KeyValuePair {
//     name: String,
//     value: String,
// }
deserializer_for!(user, value);
