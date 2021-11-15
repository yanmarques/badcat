mod src;

extern crate rand;

use std::{fs, error, collections};
use src::{xor, setting};
use std::path::PathBuf;

fn main() {
    match run() {
        Ok(()) => {},
        Err(error) => panic!("{}", error)
    }
}

fn run() -> Result<(), Box<dyn error::Error>> {
    let raw_settings: json::JsonValue = load_settings()?;

    let setting = parse_settings(&raw_settings);

    let mut replacements = collections::HashMap::new();
    replacements.insert("@{ENC_KEY}", &setting.key);

    let enc_windows_url = xor::encode(&setting.key, &setting.windows_url);
    replacements.insert("@{ENC_WINDOWS_URL}", &enc_windows_url);

    let enc_linux_url = xor::encode(&setting.key, &setting.linux_url);
    replacements.insert("@{ENC_LINUX_URL}", &enc_linux_url);

    let enc_windows_path = xor::encode(
        &setting.key,
        &String::from(setting.windows_path.to_str().unwrap())
    );
    replacements.insert("@{ENC_WINDOWS_PATH}", &enc_windows_path);

    let enc_linux_path = xor::encode(
        &setting.key,
        &String::from(setting.linux_path.to_str().unwrap())
    );
    replacements.insert("@{ENC_LINUX_PATH}", &enc_linux_path);

    replace_settings(&replacements)?;

    Ok(())
}

fn load_settings() -> Result<json::JsonValue, Box<dyn error::Error>> {
    let source = fs::read_to_string("settings.json")?;
    Ok(json::parse(&source)?)
}

fn replace_settings(replacements: &collections::HashMap<&str, &String>) -> Result<(), Box<dyn error::Error>> {
    let mut config_source = fs::read_to_string("config.rs.template")?;

    for (pattern, &content) in replacements {
        config_source = config_source.replace(pattern, &content);
    }

    fs::write("src/config.rs", config_source)?;
    Ok(())
}

fn parse_settings(raw: &json::JsonValue) -> setting::Setting {
    let key;
    if raw.has_key("key") {
        key = String::from(
            raw["key"].as_str().unwrap_or_else(|| {
                panic!("key must be a string");
            })
        );
    } else {
        key = xor::secret_key();
    }

    let windows_url = String::from(
        raw["tor_urls"]["windows"]
            .as_str()
            .unwrap_or_else(|| {
                panic!("windows url must be a string");
            })
    );

    let linux_url = String::from(
        raw["tor_urls"]["linux"]
            .as_str()
            .unwrap_or_else(|| {
                panic!("linux url must be a string");
            })
    );

    let windows_path = PathBuf::from(
        raw["tor_dst"]["windows"]
            .as_str()
            .unwrap_or_else(|| {
                panic!("windows path must be a string");
            })
    );

    let linux_path = PathBuf::from(
        raw["tor_dst"]["linux"]
            .as_str()
            .unwrap_or_else(|| {
                panic!("linux path must be a string");
            })
    );

    setting::Setting {
        key,
        windows_url,
        linux_url,
        windows_path,
        linux_path
    }
}