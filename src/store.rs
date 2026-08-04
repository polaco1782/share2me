use std::{
    fs::{self, File, OpenOptions},
    io::{BufReader, Read, Seek, SeekFrom, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::AsyncWriteExt;

pub const MAX_UPLOAD_BYTES: u64 = 512 * 1024 * 1024;
const MAX_METADATA_BYTES: u64 = 64 * 1024;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("invalid filename")]
    InvalidFilename,
    #[error("no file provided")]
    EmptyUpload,
    #[error("file exceeds the 512 MiB upload limit")]
    TooLarge,
    #[error("file not found")]
    NotFound,
    #[error("stored file failed its SHA-256 integrity check")]
    Integrity,
    #[error("storage I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid metadata: {0}")]
    Metadata(#[from] serde_json::Error),
}

#[derive(Clone, Debug)]
pub struct FileStore {
    data_dir: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FileMetadata {
    pub id: String,
    pub hash: String,
    pub filename: String,
    #[serde(default)]
    pub single_download: bool,
    #[serde(default)]
    pub encrypted: bool,
    #[serde(default)]
    pub content_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
}

#[derive(Debug)]
pub struct UploadResult {
    pub token: String,
    pub sha256: String,
}

#[derive(Debug)]
pub struct PendingUpload {
    store: FileStore,
    token: String,
    temp_path: PathBuf,
    file: tokio::fs::File,
    hasher: Sha256,
    size: u64,
    committed: bool,
}

#[derive(Debug)]
pub struct OpenedFile {
    pub file: File,
    pub size: u64,
}

impl FileStore {
    pub fn new(data_dir: PathBuf) -> Result<Self, StorageError> {
        fs::create_dir_all(&data_dir)?;
        fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700))?;
        let data_dir = fs::canonicalize(data_dir)?;
        Ok(Self { data_dir })
    }

    pub fn rebase_after_chroot(&mut self) {
        self.data_dir = PathBuf::from("/");
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn begin_upload(&self) -> Result<PendingUpload, StorageError> {
        for _ in 0..32 {
            let token = format!("{:032x}", rand::random::<u128>());
            let temp_path = self.data_dir.join(format!(".{token}.upload"));
            let open_result = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temp_path);

            match open_result {
                Ok(file) => {
                    if self.data_dir.join(&token).exists() || self.metadata_path(&token).exists() {
                        drop(file);
                        let _ = fs::remove_file(&temp_path);
                        continue;
                    }
                    return Ok(PendingUpload {
                        store: self.clone(),
                        token,
                        temp_path,
                        file: tokio::fs::File::from_std(file),
                        hasher: Sha256::new(),
                        size: 0,
                        committed: false,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not allocate a unique upload token",
        )
        .into())
    }

    pub async fn load_metadata(&self, token: &str) -> Result<FileMetadata, StorageError> {
        if !is_valid_token(token) {
            return Err(StorageError::NotFound);
        }
        let path = self.metadata_path(token);
        let token = token.to_owned();
        tokio::task::spawn_blocking(move || {
            let file = open_no_follow(&path)?;
            if file.metadata()?.len() > MAX_METADATA_BYTES {
                return Err(StorageError::NotFound);
            }
            let mut bytes = Vec::new();
            file.take(MAX_METADATA_BYTES + 1).read_to_end(&mut bytes)?;
            if bytes.len() as u64 > MAX_METADATA_BYTES {
                return Err(StorageError::NotFound);
            }
            let metadata: FileMetadata = serde_json::from_slice(&bytes)?;
            if metadata.id != token
                || !is_safe_filename(&metadata.filename)
                || !is_valid_sha256(&metadata.hash)
                || !is_valid_content_type(&metadata.content_type)
            {
                return Err(StorageError::NotFound);
            }
            Ok(metadata)
        })
        .await
        .map_err(std::io::Error::other)?
    }

    pub async fn open_verified(&self, metadata: &FileMetadata) -> Result<OpenedFile, StorageError> {
        if !is_valid_token(&metadata.id) || !is_valid_sha256(&metadata.hash) {
            return Err(StorageError::NotFound);
        }
        let path = self.data_path(&metadata.id);
        let expected_hash = metadata.hash.clone();
        tokio::task::spawn_blocking(move || {
            let file = open_no_follow(&path)?;
            let file_metadata = file.metadata()?;
            if !file_metadata.is_file() || file_metadata.len() > MAX_UPLOAD_BYTES {
                return Err(StorageError::NotFound);
            }

            let mut reader = BufReader::with_capacity(64 * 1024, file);
            let mut hasher = Sha256::new();
            let mut buffer = vec![0_u8; 64 * 1024];
            loop {
                let count = reader.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                hasher.update(&buffer[..count]);
            }
            let actual_hash = hex::encode(hasher.finalize());
            if actual_hash != expected_hash {
                return Err(StorageError::Integrity);
            }
            reader.seek(SeekFrom::Start(0))?;
            Ok(OpenedFile {
                file: reader.into_inner(),
                size: file_metadata.len(),
            })
        })
        .await
        .map_err(std::io::Error::other)?
    }

    pub async fn remove(&self, metadata: &FileMetadata) -> Result<(), StorageError> {
        if !is_valid_token(&metadata.id) {
            return Err(StorageError::NotFound);
        }
        let data_path = self.data_path(&metadata.id);
        let metadata_path = self.metadata_path(&metadata.id);
        tokio::task::spawn_blocking(move || {
            remove_if_present(&metadata_path)?;
            remove_if_present(&data_path)?;
            sync_parent(&metadata_path)?;
            Ok(())
        })
        .await
        .map_err(std::io::Error::other)?
    }

    pub async fn remove_if_expired(&self, metadata: &FileMetadata) -> Result<bool, StorageError> {
        if !metadata.is_expired() {
            return Ok(false);
        }
        self.remove(metadata).await?;
        tracing::info!(token = %metadata.id, "expired file removed on access");
        Ok(true)
    }

    pub fn sweep_expired(&self) -> Result<usize, StorageError> {
        let mut removed = 0;
        for entry in fs::read_dir(&self.data_dir)? {
            let entry = entry?;
            let path = entry.path();
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let Some(token) = name.strip_suffix(".json") else {
                continue;
            };
            if !is_valid_token(token) || entry.file_type()?.is_symlink() {
                continue;
            }
            let metadata = match read_metadata_sync(&path, token) {
                Ok(metadata) => metadata,
                Err(error) => {
                    tracing::warn!(path = %path.display(), %error, "skipping invalid metadata");
                    continue;
                }
            };
            if metadata.is_expired() {
                remove_if_present(&path)?;
                remove_if_present(&self.data_path(&metadata.id))?;
                tracing::info!(token = %metadata.id, "expired file removed by housekeeper");
                removed += 1;
            }
        }
        if removed > 0 {
            sync_directory(&self.data_dir)?;
        }
        Ok(removed)
    }

    fn metadata_path(&self, token: &str) -> PathBuf {
        self.data_dir.join(format!("{token}.json"))
    }

    fn data_path(&self, token: &str) -> PathBuf {
        self.data_dir.join(token)
    }
}

impl FileMetadata {
    pub fn is_expired(&self) -> bool {
        self.expires_at
            .is_some_and(|expires_at| now_unix() >= expires_at)
    }
}

impl PendingUpload {
    pub async fn write_chunk(&mut self, bytes: &[u8]) -> Result<(), StorageError> {
        let new_size = self
            .size
            .checked_add(bytes.len() as u64)
            .ok_or(StorageError::TooLarge)?;
        if new_size > MAX_UPLOAD_BYTES {
            return Err(StorageError::TooLarge);
        }
        self.file.write_all(bytes).await?;
        self.hasher.update(bytes);
        self.size = new_size;
        Ok(())
    }

    pub async fn commit(
        mut self,
        filename: String,
        single_download: bool,
        expire_seconds: Option<u64>,
        encrypted: bool,
        content_type: String,
    ) -> Result<UploadResult, StorageError> {
        if self.size == 0 {
            return Err(StorageError::EmptyUpload);
        }
        if !is_safe_filename(&filename) {
            return Err(StorageError::InvalidFilename);
        }

        self.file.flush().await?;
        self.file.sync_data().await?;

        let sha256 = hex::encode(self.hasher.clone().finalize());
        let final_path = self.store.data_dir.join(&self.token);
        rename_no_replace(&self.temp_path, &final_path)?;
        self.temp_path = final_path.clone();
        sync_directory(&self.store.data_dir)?;

        let expires_at = expire_seconds.and_then(|seconds| {
            i64::try_from(seconds)
                .ok()
                .and_then(|seconds| now_unix().checked_add(seconds))
        });
        let metadata = FileMetadata {
            id: self.token.clone(),
            hash: sha256.clone(),
            filename,
            single_download,
            encrypted,
            content_type,
            expires_at,
        };
        let metadata_path = self.store.metadata_path(&self.token);
        let metadata_bytes = serde_json::to_vec_pretty(&metadata)?;

        let write_result = tokio::task::spawn_blocking(move || {
            atomic_write(&metadata_path, &metadata_bytes, 0o600)
        })
        .await
        .map_err(std::io::Error::other)?;
        if let Err(error) = write_result {
            let _ = tokio::fs::remove_file(&final_path).await;
            return Err(error.into());
        }

        self.committed = true;
        Ok(UploadResult {
            token: self.token.clone(),
            sha256,
        })
    }
}

impl Drop for PendingUpload {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_file(&self.temp_path);
        }
    }
}

pub fn is_valid_token(token: &str) -> bool {
    token.len() == 32
        && token
            .bytes()
            .all(|character| character.is_ascii_digit() || (b'a'..=b'f').contains(&character))
}

fn is_valid_sha256(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|character| character.is_ascii_digit() || (b'a'..=b'f').contains(&character))
}

fn is_valid_content_type(content_type: &str) -> bool {
    content_type.len() <= 127
        && content_type
            .parse::<mime::Mime>()
            .is_ok_and(|value| value.essence_str() == content_type)
}

pub fn is_safe_filename(filename: &str) -> bool {
    !filename.is_empty()
        && filename != "."
        && filename != ".."
        && !filename.starts_with('.')
        && filename.len() <= 255
        && !filename.contains(['/', '\\', '"', '\0'])
        && !filename.chars().any(char::is_control)
        && !filename.contains(['\u{ff0e}', '\u{2024}', '\u{fe52}'])
}

fn rename_no_replace(old_path: &Path, new_path: &Path) -> Result<(), std::io::Error> {
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        old_path,
        rustix::fs::CWD,
        new_path,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(Into::into)
}

fn open_no_follow(path: &Path) -> Result<File, std::io::Error> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

fn read_metadata_sync(path: &Path, token: &str) -> Result<FileMetadata, StorageError> {
    let file = open_no_follow(path)?;
    if file.metadata()?.len() > MAX_METADATA_BYTES {
        return Err(StorageError::NotFound);
    }
    let mut bytes = Vec::new();
    file.take(MAX_METADATA_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_METADATA_BYTES {
        return Err(StorageError::NotFound);
    }
    let metadata: FileMetadata = serde_json::from_slice(&bytes)?;
    if metadata.id != token
        || !is_safe_filename(&metadata.filename)
        || !is_valid_sha256(&metadata.hash)
        || !is_valid_content_type(&metadata.content_type)
    {
        return Err(StorageError::NotFound);
    }
    Ok(metadata)
}

fn atomic_write(path: &Path, contents: &[u8], mode: u32) -> Result<(), std::io::Error> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| std::io::Error::other("invalid output path"))?;
    let temp_path = path.with_file_name(format!(".{file_name}.{:016x}.tmp", rand::random::<u64>()));
    let mut temp = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&temp_path)?;
    let result = (|| {
        temp.write_all(contents)?;
        temp.sync_all()?;
        fs::set_permissions(&temp_path, fs::Permissions::from_mode(mode))?;
        rename_no_replace(&temp_path, path)?;
        if let Err(error) = sync_parent(path) {
            let _ = fs::remove_file(path);
            let _ = sync_parent(path);
            return Err(error);
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp_path);
    }
    result
}

fn sync_parent(path: &Path) -> Result<(), std::io::Error> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    sync_directory(parent)
}

fn sync_directory(path: &Path) -> Result<(), std::io::Error> {
    File::open(path)?.sync_all()
}

fn remove_if_present(path: &Path) -> Result<(), std::io::Error> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
        .try_into()
        .unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use tempfile::tempdir;

    use super::*;

    #[tokio::test]
    async fn stores_and_verifies_a_file() {
        let directory = tempdir().unwrap();
        let store = FileStore::new(directory.path().to_path_buf()).unwrap();
        assert_eq!(
            fs::metadata(store.data_dir()).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let mut upload = store.begin_upload().unwrap();
        upload.write_chunk(b"hello").await.unwrap();
        let result = upload
            .commit(
                "hello.txt".to_owned(),
                false,
                None,
                false,
                "text/plain".to_owned(),
            )
            .await
            .unwrap();

        let metadata = store.load_metadata(&result.token).await.unwrap();
        let opened = store.open_verified(&metadata).await.unwrap();
        assert_eq!(opened.size, 5);
        assert_eq!(result.sha256.len(), 64);
        assert_eq!(result.token.len(), 32);
    }

    #[tokio::test]
    async fn refuses_symlinked_content() {
        let directory = tempdir().unwrap();
        let store = FileStore::new(directory.path().to_path_buf()).unwrap();
        let target = directory.path().join("target");
        fs::write(&target, b"secret").unwrap();
        let metadata = FileMetadata {
            id: "0123456789abcdef0123456789abcdef".to_owned(),
            hash: "2bb80d537b1da3e38bd30361aa855686bde0ba7b65023a3d1a69374b8d8a3b52".to_owned(),
            filename: "secret.txt".to_owned(),
            single_download: false,
            encrypted: false,
            content_type: "text/plain".to_owned(),
            expires_at: None,
        };
        symlink(&target, directory.path().join(&metadata.id)).unwrap();
        assert!(store.open_verified(&metadata).await.is_err());
    }

    #[test]
    fn validates_public_identifiers() {
        assert!(!is_valid_token("0123456789abcdef"));
        assert!(is_valid_token("0123456789abcdef0123456789abcdef"));
        assert!(!is_valid_token("0123456789abcdeg"));
        assert!(is_safe_filename("résumé.txt"));
        assert!(!is_safe_filename("../secret"));
        assert!(!is_safe_filename(".hidden"));
        assert!(!is_safe_filename("fullwidth\u{ff0e}txt"));
    }
}
