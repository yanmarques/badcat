use std::fs::File;
use std::io::BufWriter;

const WINDOWS_URL: &str = "https://dist.torproject.org/torbrowser/11.0/tor-win32-0.4.6.8.zip";

fn main() {
    download(WINDOWS_URL, "tor-win32-0.4.6.8.zip");
}

fn download(url: &str, path: &str) {
    let mut res = match reqwest::blocking::get(url) {
        Ok(res) => res,
        Err(err) => panic!("failed to download: {}", err)
    };

    let file = match File::create(path) {
        Ok(file) => file,
        Err(err) => panic!("failed to create file: {}", err)
    };

    let mut writer = BufWriter::new(file);

    match res.copy_to(&mut writer) {
        Ok(_) => {},
        Err(err) => panic!("failed to write download file: {}", err)
    };
}
