use std::path::PathBuf;

pub struct Setting {
    pub key: String,
    pub name: String,
    pub tor_dir: PathBuf,
    pub torrc: String
}