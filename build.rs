mod src;

extern crate rand;

use std::{fs, error, collections};
use src::{xor, setting};
use std::path::PathBuf;

const CFG_TEMPLATE: &str = "config.rs.template";
const CFG_DESTINATION: &str = "src/config.rs";

struct BuildSetting {
    key: String,
    windows_url: String,
    windows_dir: String,
    linux_url: String,
    linux_dir: String,
    torrc: String
}

fn main() -> Result<(), Box<dyn error::Error>> {
    let raw_settings: json::JsonValue = load_settings()?;

    let setting = parse_settings(&raw_settings);

    let mut replacements = collections::HashMap::new();
    replacements.insert("@{ENC_KEY}", setting.key.clone());

    if cfg!(windows) {
        replacements.insert("@{TOR_DIR}", setting.windows_dir.clone());

        let enc_windows_url = xor::encode(&setting.key, &setting.windows_url);
        replacements.insert("@{ENC_TOR_URL}", enc_windows_url);

        let enc_windows_dir = xor::encode(
            &setting.key,
            &setting.windows_dir
        );
        replacements.insert("@{ENC_TOR_DIR}", enc_windows_dir);
    } else {
        replacements.insert("@{TOR_DIR}", setting.linux_dir.clone());

        let enc_linux_url = xor::encode(&setting.key, &setting.linux_url);
        replacements.insert("@{ENC_TOR_URL}", enc_linux_url);

        let enc_linux_dir = xor::encode(
            &setting.key,
            &setting.linux_dir
        );
        replacements.insert("@{ENC_TOR_DIR}", enc_linux_dir);
    }

    match replace_settings(
        &setting.torrc,
        &replacements
    ) {
        Ok(torrc) => {
            let enc_torrc = xor::encode(&setting.key, &torrc);
            replacements.insert("@{ENC_TORRC}", enc_torrc);
        },
        Err(error) => return Result::Err(error)
    };

    match replace_settings(
        &String::from(CFG_TEMPLATE),
        &replacements
    ) {
        Ok(data) => fs::write(CFG_DESTINATION, data)?,
        Err(error) => return Result::Err(error)
    };

    Ok(())
}

fn load_settings() -> Result<json::JsonValue, Box<dyn error::Error>> {
    let source = fs::read_to_string("settings.json")?;
    Ok(json::parse(&source)?)
}

fn replace_settings(
    template: &String,
    replacements: &collections::HashMap<&str, String>
) -> Result<String, Box<dyn error::Error>> {
    let mut config_source = fs::read_to_string(template)?;

    for (pattern, content) in replacements {
        config_source = config_source.replace(pattern, &content);
    }

    Ok(config_source)
}

fn parse_settings(raw: &json::JsonValue) -> BuildSetting {
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

    let windows_dir = String::from(
        raw["tor_dirs"]["windows"]
            .as_str()
            .unwrap_or_else(|| {
                panic!("windows path must be a string");
            })
    );

    let linux_dir = String::from(
        raw["tor_dirs"]["linux"]
            .as_str()
            .unwrap_or_else(|| {
                panic!("linux path must be a string");
            })
    );

    let torrc = String::from(
        raw["torrc"]
            .as_str()
            .unwrap_or_else(|| {
                panic!("torrc must be a string");
            })
    );

    BuildSetting {
        key,
        windows_url,
        windows_dir,
        linux_url,
        linux_dir,
        torrc
    }
}