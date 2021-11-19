use std::path::PathBuf;
use std::{error, fs};

use json::JsonValue;

pub struct Setting {
    pub address: String,
    pub uses_payload: bool,
}

pub fn from(path: &PathBuf) -> Result<Vec<Setting>, Box<dyn error::Error>> {
    let json = load_json(path)?;
    let settings = parse_json(&json)?;
    Ok(settings)
}

fn load_json(path: &PathBuf) -> Result<JsonValue, Box<dyn error::Error>> {
    let source = fs::read_to_string(path)?;
    Ok(json::parse(&source)?)
}

fn parse_json(settings: &JsonValue) -> Result<Vec<Setting>, Box<dyn error::Error>> {
    let result = settings
        .members()
        .map(|inner| {
            let address = String::from(inner["address"].as_str().unwrap_or_else(|| {
                panic!("invalid address settings");
            }));

            let uses_payload = inner["uses_payload"].as_bool().unwrap_or(false);

            Setting {
                address,
                uses_payload,
            }
        })
        .collect();

    Ok(result)
}

