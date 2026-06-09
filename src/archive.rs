use std::fs::{self, File, FileTimes};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use typed_path::Utf8WindowsPath;
use std::mem::size_of;
use std::time::{Duration, UNIX_EPOCH};
use walkdir::{WalkDir, IntoIter};

use crate::{CHUNK_SIZE, Result};
use crate::common_io::{ReadChunk, WriteFiles};


const TYPE_FILE:         u8 = 0x00;
const TYPE_DIRECTORY:    u8 = 0x01;
const TYPE_SYMLINK_FILE: u8 = 0x02;
const TYPE_SYMLINK_DIR:  u8 = 0x03;
const TYPE_UNIX:         u8 = 0x00;
const TYPE_WINDOWS:      u8 = 0x10;
const ARCHIVE_HEADER_LENGTH_SIZE: usize = 2;


pub struct ArchiveRead {
    walk_dir: IntoIter,
    f_in: Option<File>,
    data_size: u64,
    buf_out: Vec<u8>,
    no_more_files: bool,
}

impl ArchiveRead {
    pub fn new(f_in_path: &Path) -> Self {
        // in a directory: list files first, then sub-directories
        let walk_dir = WalkDir::new(f_in_path).sort_by_key(|x| x.file_type().is_dir()).into_iter();
        let buf_out = Vec::with_capacity(CHUNK_SIZE * 3);

        Self { walk_dir, f_in: None, data_size: 0, buf_out, no_more_files: false }
    }

    fn build_archive_header(entry: &walkdir::DirEntry) -> Result<(Vec<u8>, Option<std::path::PathBuf>)> {
        // archive header initialized with place holder for header size 
        let mut archive_header = vec![0u8; ARCHIVE_HEADER_LENGTH_SIZE];

        let mut entry_type = if entry.file_type().is_file() {
            TYPE_FILE
        } else if entry.file_type().is_dir() {
            TYPE_DIRECTORY
        } else if entry.file_type().is_symlink() {
            // whether a symlink is a file or a directory is only relevant for windows (when creating them there)
            if entry.path().is_dir() {
                TYPE_SYMLINK_DIR
            } else {
                // if target of symlink does not exist (hence it can't be evaluated 
                // whether it is a file or a directory), type file is used  
                TYPE_SYMLINK_FILE
            }
        } else {
            return Err(format!("Ignored unsupported file type for archive: {}", entry.path().display()).into());
        };

        if cfg!(windows) {
            entry_type |= TYPE_WINDOWS;
        } else {
            entry_type |= TYPE_UNIX;
        }
        archive_header.push(entry_type);

        // path length and path (including filename)
        let path_string = if entry.file_type().is_dir() {
            entry.path().to_string_lossy()
        } else {
            entry.file_name().to_string_lossy()
        };
        let path_len: u16 = path_string.len().try_into()?;
        archive_header.extend(path_len.to_le_bytes());
        archive_header.extend(path_string.as_bytes());

        // last access time 
        let time_accessed = entry.metadata()?.accessed()?.duration_since(UNIX_EPOCH)?.as_secs();
        archive_header.extend(time_accessed.to_le_bytes());
        // last modification time
        let time_modified = entry.metadata()?.modified()?.duration_since(UNIX_EPOCH)?.as_secs();
        archive_header.extend(time_modified.to_le_bytes());

        if entry.file_type().is_file() {
            // file size
            let file_size = entry.metadata()?.len();
            archive_header.extend(file_size.to_le_bytes());

        } else if entry.file_type().is_symlink() {
            // target path of symlink
            let target_path = fs::read_link(entry.path())?;
            let target_path_string = target_path.to_string_lossy();
            let target_path_len: u16 = target_path_string.len().try_into()?;
            archive_header.extend(target_path_len.to_le_bytes());
            archive_header.extend(target_path_string.as_bytes());
        }

        // permissions
        let mut perm: u16 = 0;
        if cfg!(unix) && (entry.file_type().is_file() || entry.file_type().is_dir()) {
            use std::os::unix::fs::PermissionsExt;
            let permission_mode = entry.metadata()?.permissions().mode();
            // use 12 least significant bits
            perm = (permission_mode & 0x0FFF) as u16;
        }
        archive_header.extend(perm.to_le_bytes());

        // header size
        let header_size: [u8; ARCHIVE_HEADER_LENGTH_SIZE] = u16::try_from(archive_header.len() - 2)?.to_le_bytes();
        archive_header[0] = header_size[0];
        archive_header[1] = header_size[1];

        let mut path = None;
        if entry.file_type().is_file() {
            path = Some(entry.clone().into_path());
        }

        Ok((archive_header, path))
    }

    fn get_next_archive_item(&mut self) -> Result<(Option<Vec<u8>>, Option<std::path::PathBuf>)> {
        if let Some(entry) = self.walk_dir.next() {
            match &entry {
                Ok(entry) => {
                    match Self::build_archive_header(entry) {
                        Ok((archive_header, filepath)) => Ok((Some(archive_header), filepath)),
                        Err(e) => Err(format!("Skipped entry {}   Error: {e}", entry.path().display()).into())
                    }
                },
                Err(e) => Err(format!("Skipped entry {entry:?}   Error: {e}").into())
            }
        } else {
            // no more entries
            Ok((None, None))
        }
    }
}

impl ReadChunk for ArchiveRead {
    fn read_chunk(&mut self) -> Result<(Vec<u8>, bool)> {

        while !self.no_more_files {
            // buffer 2 chunks, hence read ahead 1 chunk to detect the final file and final-chunk flag can be set on the last chunk 
            if self.buf_out.len() > 2 * CHUNK_SIZE {
                let chunk = self.buf_out.drain(..CHUNK_SIZE).collect();
                return Ok((chunk, false));
            }

            if self.data_size == 0 {
                let archive_header; 
                let filepath;

                match self.get_next_archive_item() {
                    Ok(values) => (archive_header, filepath) = values,
                    Err(e) => { 
                        eprintln!("{e}"); 
                        continue; 
                    }
                }

                if let Some(filepath) = &filepath {
                    if let Ok(f_in) = File::open(filepath) {
                        self.data_size = f_in.metadata()?.len();
                        self.f_in = Some(f_in);
                    } else {
                        eprintln!("Could not open - skipped: {}", filepath.display());
                        continue;
                    }
                }

                // if file could not be opened, its admin data should be skipped, 
                // therefore save the admin data after the file handling,
                // but for directories it is required
                if let Some(hdr) = &archive_header {
                    self.buf_out.extend(hdr);
                } else {
                    self.no_more_files = true;
                }
            } else {
                let buf_len = CHUNK_SIZE.min(self.data_size.try_into()?);
                let mut buf_read = vec![0u8; buf_len];

                self.f_in.as_ref().unwrap().read_exact(&mut buf_read)?;
                self.data_size -= u64::try_from(buf_len)?;

                self.buf_out.extend(buf_read);
            }
        }

        if self.buf_out.len() > CHUNK_SIZE {
            let chunk = self.buf_out.drain(..CHUNK_SIZE).collect();
            return Ok((chunk, false));
        }

        // set final chunk flag
        Ok((self.buf_out.clone(), true))
    }
}


#[derive(Default)]
pub struct ArchiveWrite {
    f_out: Option<File>,
    buf_out: Vec<u8>,
    header_length: Option<usize>,
    file_size: u64, 
    file_times: FileTimes,
    file_path: PathBuf,
    dir_path: PathBuf,
}

impl ArchiveWrite {
    pub fn new() -> Self { 
        let buf_out = Vec::with_capacity(CHUNK_SIZE * 2);
        Self { f_out: None, buf_out, header_length: None, file_size: 0, file_times: FileTimes::new(), 
            file_path: PathBuf::new(), dir_path: PathBuf::new() }
    }

    fn get_path_from_header(header: &[u8], current_end_index: usize, created_on_os_type: u8) -> Result<(String, usize)> {
        // new start index of header field
        let mut s = current_end_index;
        // new end index of header field
        let mut e = current_end_index + size_of::<u16>();

        // path length                
        let path_len = u16::from_le_bytes(header[s..e].try_into()?);
        // path
        s = e; e += usize::from(path_len);
        let path_bytes = &header[s..e];
        let path_str = str::from_utf8(path_bytes)?;
        // convert Windows path to unix path, it on unix (windows can handle unix path)
        let entry_path = if cfg!(unix) && created_on_os_type == TYPE_WINDOWS { 
            Utf8WindowsPath::new(path_str).with_unix_encoding().to_string()
        } else {
            path_str.to_string()
        };

        Ok((entry_path, e))
    }

    fn eval_header(&mut self, header: &[u8]) -> Result<()> {
        // type
        let file_type          = header[0] & 0x0F;
        let created_on_os_type = header[0] & 0xF0;

        let mut s ;
        let mut e = 1;

        // entry's path
        let entry_path;
        (entry_path, e) = Self::get_path_from_header(header, e, created_on_os_type)?;

        // access time
        s = e; e += size_of::<u64>(); 
        let time_accessed_seconds = u64::from_le_bytes( header[s..e].try_into()? );
        let time_accessed = UNIX_EPOCH + Duration::from_secs(time_accessed_seconds);
        // modification time
        s = e; e += size_of::<u64>(); 
        let time_modified_seconds = u64::from_le_bytes( header[s..e].try_into()? );
        let time_modified = UNIX_EPOCH + Duration::from_secs(time_modified_seconds);
        self.file_times = FileTimes::new()
            .set_accessed(time_accessed)
            .set_modified(time_modified);

        // create type
        if file_type == TYPE_DIRECTORY {
            fs::create_dir_all(&entry_path)?;
            self.dir_path = PathBuf::from(&entry_path);
            // set timestamps of directory
            if !File::open(&entry_path).is_ok_and(|dir| dir.set_times(self.file_times).is_ok()) {
                eprintln!("Could not set timestamps for directory {}", entry_path);  
            }
        } else if file_type == TYPE_FILE {
            self.file_path = self.dir_path.join(&entry_path);
            self.f_out = Some( File::create(&self.file_path)? );
            
            // file size
            s = e; e += size_of::<u64>(); 
            self.file_size = u64::from_le_bytes( header[s..e].try_into()? );
        } else if file_type == TYPE_SYMLINK_FILE || file_type == TYPE_SYMLINK_DIR {
            // symlink's target path
            let target_path;
            (target_path, e) = Self::get_path_from_header(header, e, created_on_os_type)?;

            let sym_path = self.dir_path.join(&entry_path);

            // create symlink
            // remove it, if it already exists, otherwise symlink can't be created
            let _ = fs::remove_file(&sym_path);
            #[cfg(unix)]
            {
                std::os::unix::fs::symlink(target_path, &sym_path)?;
            }
            #[cfg(windows)]
            {
                if file_type == TYPE_SYMLINK_FILE {
                    std::os::windows::fs::symlink_file(&target_path, &sym_path)?;
                }
                if file_type == TYPE_SYMLINK_DIR {
                    std::os::windows::fs::symlink_dir(&target_path, &sym_path)?;
                }
            }
        } else {
            return Err(format!("Archive contains unknown file type: {file_type}").into());
        }

        // permissions
        // if this is a unix system and the archive was created on a unix system, set permission mode
        if cfg!(unix) && created_on_os_type == TYPE_UNIX && (file_type == TYPE_DIRECTORY || file_type == TYPE_FILE) {
            s = e; e += size_of::<u16>();
            let perm = u16::from_le_bytes( header[s..e].try_into()? );

            let path = if file_type == TYPE_FILE {
                &self.file_path
            } else {
                &self.dir_path
            };
            let fd = File::open(path)?;
            let mut permissions = fd.metadata()?.permissions();
            let mode_masked = permissions.mode() & 0xFFFF_F000;
            permissions.set_mode(mode_masked | u32::from(perm & 0x0FFF));
            fd.set_permissions(permissions)?;
        }

        Ok(())
    }
}

impl WriteFiles for ArchiveWrite {
    fn write_files(&mut self, buf_in: &[u8]) -> Result<()> {
        self.buf_out.extend(buf_in);

        while !self.buf_out.is_empty() {
            if let Some(mut f_out) = self.f_out.as_ref() {
                // write to file
                if (self.buf_out.len() as u64) < self.file_size {
                    f_out.write_all(&self.buf_out)?;
                    self.file_size -= self.buf_out.len() as u64;
                    self.buf_out.clear();
                } else {
                    let file_data: Vec<u8> = self.buf_out.drain(..usize::try_from(self.file_size)?).collect();
                    f_out.write_all(&file_data)?;
                    // set file times after all data has been written
                    if f_out.set_times(self.file_times).is_err() {
                        eprintln!("Could not set timestamps for file {}", self.file_path.display());
                    }
                    self.file_size = 0;
                    self.f_out = None;
                }
            } else if let Some(header_length) = self.header_length {
                if self.buf_out.len() >= header_length {
                    // get header
                    let header: Vec<u8> = self.buf_out.drain(..header_length).collect();

                    self.eval_header(&header)?;

                    self.header_length = None;
                } else {
                    break; // not enough data
                }
            } else if self.buf_out.len() >= ARCHIVE_HEADER_LENGTH_SIZE {
                // get header length
                let header_length_bytes: Vec<u8> = self.buf_out.drain(..ARCHIVE_HEADER_LENGTH_SIZE).collect();
                self.header_length = Some( u16::from_le_bytes(header_length_bytes.try_into().unwrap()).into() );
            } else {
                break; // not enough data
            }
        }
        Ok(())
    }
}
