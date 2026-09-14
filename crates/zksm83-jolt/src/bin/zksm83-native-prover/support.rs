//! Bounded file, publication, and hashing support for the native prover CLI.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

use super::CliError;

pub(super) fn load_file_bounded(
    path: &Path,
    kind: &'static str,
    maximum: u64,
) -> Result<Vec<u8>, CliError> {
    let metadata = fs::metadata(path).map_err(|source| io_error("inspect", path, source))?;
    if metadata.len() > maximum {
        return Err(CliError::FileTooLarge {
            kind,
            path: path.display().to_string(),
            maximum,
        });
    }
    fs::read(path).map_err(|source| io_error("read", path, source))
}

pub(super) fn open_new(path: &Path) -> Result<File, CliError> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| io_error("create", path, source))
}

pub(super) fn open_existing(path: &Path) -> Result<File, CliError> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|source| io_error("open", path, source))
}

pub(super) fn write_new(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    require_absent(path)?;
    let temporary = partial_path(path);
    let mut file = open_new(&temporary)?;
    file.write_all(bytes)
        .map_err(|source| io_error("write", &temporary, source))?;
    file.sync_all()
        .map_err(|source| io_error("sync", &temporary, source))?;
    require_absent(path)?;
    fs::rename(&temporary, path).map_err(|source| io_error("publish", path, source))?;
    sync_parent_directory(path)
}

pub(super) fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    let temporary = partial_path(path);
    let mut file = open_new(&temporary)?;
    file.write_all(bytes)
        .map_err(|source| io_error("write", &temporary, source))?;
    file.sync_all()
        .map_err(|source| io_error("sync", &temporary, source))?;
    fs::rename(&temporary, path).map_err(|source| io_error("publish", path, source))?;
    sync_parent_directory(path)
}

pub(super) fn sync_parent_directory(path: &Path) -> Result<(), CliError> {
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let directory =
        File::open(parent).map_err(|source| io_error("open directory", parent, source))?;
    directory
        .sync_all()
        .map_err(|source| io_error("sync directory", parent, source))
}

pub(super) fn require_absent(path: &Path) -> Result<(), CliError> {
    if path.exists() {
        Err(CliError::OutputExists(path.display().to_string()))
    } else {
        Ok(())
    }
}

pub(super) fn partial_path(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(format!(".partial.{}", std::process::id()));
    PathBuf::from(value)
}

pub(super) fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub(super) fn sha256_reader(
    reader: &mut (impl Read + Seek),
    expected_length: u64,
    path: &Path,
) -> Result<[u8; 32], CliError> {
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|source| io_error("seek", path, source))?;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|source| io_error("read", path, source))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(
                u64::try_from(read)
                    .map_err(|_| CliError::ProgressMismatch("file hash length overflow"))?,
            )
            .ok_or(CliError::ProgressMismatch("file hash length overflow"))?;
        let chunk = buffer
            .get(..read)
            .ok_or(CliError::ProgressMismatch("file hash buffer range"))?;
        hash.update(chunk);
    }
    if total != expected_length {
        return Err(CliError::ProgressMismatch(
            "spool length changed while hashing",
        ));
    }
    Ok(hash.finalize().into())
}

pub(super) fn io_error(operation: &'static str, path: &Path, source: io::Error) -> CliError {
    CliError::Io {
        operation,
        path: path.display().to_string(),
        source,
    }
}
