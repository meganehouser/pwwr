use std::io::{Read, Seek, SeekFrom, Write};
use std::fs::{File, OpenOptions};
use std::path::PathBuf;
use errors::*;

pub trait RawStore {
    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> Result<usize>;
    fn write_all(&mut self, buf: &[u8]) -> Result<()>;
}

pub struct FileRawStore {
    file: File,
}

impl FileRawStore {
    pub fn new(path: PathBuf) -> Result<FileRawStore> {
        let file: File = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path.as_path())
            .chain_err(|| format!("can't open the raw store file [{}]", path.display()))?;
        Ok(FileRawStore { file: file })
    }
}

impl RawStore for FileRawStore {
    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> Result<usize> {
        self.file
            .read_to_end(buf)
            .chain_err(|| "can't read a buffer from the raw store file.")
    }

    fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        self.file
            .seek(SeekFrom::Start(0))
            .chain_err(|| "failed to seek file")?;
        self.file
            .write_all(buf)
            .chain_err(|| "can't write a buffer to the raw store file.")
    }
}
