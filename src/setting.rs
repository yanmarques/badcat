use std::path::PathBuf;

pub struct Setting {
    pub key: String,
    pub windows_url: String,
    pub linux_url: String,
    pub windows_path: PathBuf,
    pub linux_path: PathBuf
}