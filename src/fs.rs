use std::path::PathBuf;
use std::{fs, error};

pub fn copy_dir(
    source_dir: &PathBuf,
    to_dir: &PathBuf
) -> Result<(), Box<dyn error::Error>> {
    for entry in fs::read_dir(source_dir)? {
        let entry: fs::DirEntry = entry?;
        let path = entry.path();

        if entry.file_type()?.is_dir() {
            let base_dir = path.file_name().unwrap();
            let next_dir = to_dir.join(base_dir);

            if !next_dir.exists() {
                fs::create_dir(&next_dir)?;
            }

            copy_dir(&path, &next_dir)?;
        } else {
            fs::copy(&path, to_dir.join(entry.file_name()))?;
        }
    }

    Ok(())
}