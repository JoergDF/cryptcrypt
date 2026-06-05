use std::fs::{self, File, FileTimes};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::mem::size_of;
use std::time::{Duration, UNIX_EPOCH};
use walkdir::{WalkDir, IntoIter};

use crate::{CHUNK_SIZE, Result};
use crate::common_io::{ReadChunk, WriteFiles};

const TYPE_FILE: u8 = 0;
const TYPE_DIRECTORY: u8 = 1;
const ARCHIVE_HEADER_LENGTH_SIZE: usize = 2;


pub struct ArchiveRead {
    walk_dir: IntoIter,
    f_in: Option<File>,
    data_size: u64,
    buf_out: Vec<u8>,
    no_more_files: bool,
}

impl ArchiveRead {
    pub fn new(f_in_path: PathBuf) -> Self {
        let walk_dir = WalkDir::new(&f_in_path).into_iter();
        let buf_out = Vec::with_capacity(CHUNK_SIZE * 3);

        Self { walk_dir, f_in: None, data_size: 0, buf_out, no_more_files: false }
    }

    fn get_next_file(&mut self) -> Result<(Option<Vec<u8>>, Option<std::path::PathBuf>, bool)> {
        let mut archive_header = vec![];
        // header size, place holder
        archive_header.extend([0u8; ARCHIVE_HEADER_LENGTH_SIZE]);
        
        if let Some(entry) = self.walk_dir.next() {
            if let Ok(entry) = entry {
                if entry.file_type().is_file() || entry.file_type().is_dir() {
                    if entry.file_type().is_file() {
                        // type: file
                        archive_header.push(TYPE_FILE);
                    } else {
                        // type: directory
                        archive_header.push(TYPE_DIRECTORY);
                    }

                    // path length and path (including filename)
                    let path_string = entry.path().to_string_lossy();                    
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
                    }

                    // header size
                    let header_size: [u8; ARCHIVE_HEADER_LENGTH_SIZE] = u16::try_from(archive_header.len() - 2)?.to_le_bytes();
                    archive_header[0] = header_size[0];
                    archive_header[1] = header_size[1];

                    //println!("{:?}", path_string);
                    //println!("{:x?}", archive_header);

                    let mut path = None;
                    if entry.file_type().is_file() {
                        path = Some(entry.into_path());
                    }
                    Ok( (Some(archive_header), path, false) )
                } else if entry.file_type().is_symlink() {
                    // fixme: get target path? file or directory (important for windows, also: user needs to be admin)?
                    eprintln!("Ignored Symlink: {}", entry.path().display());
                    // if entry.path_is_symlink() {
                    //     let target_path = std::fs::read_link(entry.path())?;
                    // }
                    Ok((None, None, false))
                } else {
                    eprintln!("Ignored entry: {:?}", entry);
                    Ok((None, None, false))
                }
            } else {
                // file/directory could not be accessed
                eprintln!("Error entry: {:?}", entry); // fixme: check if files/directories that could not be accessed are printed
                Ok((None, None, false))
            }
        } else {
            // no more entries
            Ok((None, None, true))
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
                let vec_in; 
                let filepath;
                (vec_in, filepath, self.no_more_files) = self.get_next_file()?;

                if vec_in.is_none() && filepath.is_none() {
                    // entry ignored
                    continue;
                }

                if let Some(filepath) = filepath {
                    if let Ok(f_in) = File::open(&filepath) {
                        self.f_in = Some(f_in);
                        self.data_size = self.f_in.as_ref().unwrap().metadata()?.len();
                    } else {
                        eprintln!("Could not open - skipped: {}", filepath.display());
                        continue;
                    }
                }

                // if file could not be opened, its admin data should be skipped, 
                // therefore save the admin data after the file handling,
                // but for directories it is required
                if let Some(vec_in) = vec_in {
                    self.buf_out.extend(vec_in);
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
}

impl ArchiveWrite {
    pub fn new() -> Self { 
        let buf_out = Vec::with_capacity(CHUNK_SIZE * 2);
        Self { f_out: None, buf_out, header_length: None, file_size: 0, file_times: FileTimes::new(), file_path: PathBuf::new() }
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

                    // type
                    let file_type = header[0];

                    // path length
                    let mut s = 1;
                    let mut e = s + size_of::<u16>();                    
                    let path_len = u16::from_le_bytes(header[s..e].try_into()?);
                    // path
                    s = e; e += usize::from(path_len);
                    let path_bytes = &header[s..e];
                    let path_str = str::from_utf8(path_bytes)?;
                    let entry_path = Path::new(path_str); 

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

                    //println!("{:?}", entry_path);

                    // create type
                    if file_type == TYPE_DIRECTORY {
                        fs::create_dir_all(entry_path)?;
                        // set timestamps of directory
                        if !File::open(entry_path).is_ok_and(|dir| dir.set_times(self.file_times).is_ok()) {
                            eprintln!("Could not set timestamps for directory {}", entry_path.display());  
                        }
                    } else if file_type == TYPE_FILE {
                        self.file_path = entry_path.to_path_buf();
                        self.f_out = Some( File::create(&self.file_path)? ); 
                        // file size
                        s = e; e += size_of::<u64>(); 
                        self.file_size = u64::from_le_bytes( header[s..e].try_into()? );
                    } else {
                        return Err(format!("Archive contains unknown file type: {file_type}").into());
                    }

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
