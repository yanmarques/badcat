use std::fs::File;
use std::io;

pub fn download(url: &String, out_file: &mut File) -> Result<(), ureq::Error> {
    let res = match ureq::get(url).call() {
        Ok(res) => res,
        Err(err) => return Result::Err(err),
    };

    // Download stream reader
    let mut reader = res.into_reader();

    io::copy(&mut reader, out_file)?;

    Ok(())
}