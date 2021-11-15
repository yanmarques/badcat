use std::path::PathBuf;

pub struct Setting {
    pub key: String,
    pub tor_url: String,
    pub tor_dir: PathBuf,
    pub torrc: String
}