mod src;

use std::{fs, error, collections};
use src::xor;

fn main() {
    let settings: json::JsonValue = load_settings().unwrap_or_else(|error| {
        panic!("problem loading settings: {:?}", error);
    });

    let key;
    if settings.has_key("key") {
        key = settings["key"]
            .as_str()
            .unwrap_or_else(|| {
                panic!("key must be a string");
            });
    } else {
        key = "abc";
    }

    let windows_url = settings["tor_urls"]["windows"]
        .as_str()
        .unwrap_or_else(|| {
            panic!("windows url must be a string");
        });

    let mut replacements = collections::HashMap::new();
    replacements.insert("@{ENC_KEY}", key);

    let enc_windows_url = xor::encode(key, windows_url);
    replacements.insert("@{ENC_WINDOWS_URL}", &enc_windows_url);

    replace_settings(&replacements).unwrap_or_else(|error| {
        panic!("problem replacing settings: {:?}", error);
    })
}

fn load_settings() -> Result<json::JsonValue, Box<dyn error::Error>> {
    let source = fs::read_to_string("settings.json")?;
    Ok(json::parse(&source)?)
}

fn replace_settings(replacements: &collections::HashMap<&str, &str>) -> Result<(), Box<dyn error::Error>> {
    let mut config_source = fs::read_to_string("config.rs.template")?;

    for (pattern, content) in replacements {
        config_source = config_source.replace(pattern, content);
    }

    fs::write("src/config.rs", config_source)?;
    Ok(())
}