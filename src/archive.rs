use std::collections::HashMap;
use std::fs::{self, File, FileTimes};
use std::io::{Read, Write};
use std::mem::{self, size_of};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, UNIX_EPOCH};
use typed_path::Utf8WindowsPath;
use walkdir::WalkDir;
use crossbeam_channel::{Receiver, Select, TryRecvError, bounded};
use num_cpus;
use filetime;
//use drill_press::{Segments, SparseFile};

use crate::common_io::{ReadChunk, WriteFiles};
use crate::{CHUNK_SIZE, Result};


const TYPE_FILE:         u8 = 0x00;
const TYPE_DIRECTORY:    u8 = 0x01;
const TYPE_SYMLINK_FILE: u8 = 0x02;
const TYPE_SYMLINK_DIR:  u8 = 0x03;
const TYPE_UNIX:         u8 = 0x00;
const TYPE_WINDOWS:      u8 = 0x10;
const ARCHIVE_HEADER_LENGTH_SIZE: usize = 2;

pub struct ArchiveRead {
    pub thread_handles: Vec<thread::JoinHandle<std::result::Result<(), String>>>,
    rx_out_receivers: Vec<Receiver<(Vec<u8>, bool)>>,
    channel_index: Option<usize>,
    channel_finished: Vec<bool>,
    buf_out: Vec<u8>,
}

impl ArchiveRead {
    pub fn new(f_in_path: &Path) -> Self {
        let num_workers = num_cpus::get(); // fixme: too much cpus? -1 for walkdir, and what about bzip,crypt?
        let mut thread_handles = Vec::with_capacity(num_workers + 1);
        let mut rx_out_receivers = Vec::with_capacity(num_workers);

        let (tx_paths, rx_paths) = bounded(num_workers * 2);

        {
            let f_in_path = f_in_path.to_path_buf();
            let tx_paths = tx_paths.clone();
            thread_handles.push(thread::spawn(move || -> std::result::Result<(), String> {
                for entry in WalkDir::new(f_in_path) {
                    match entry {
                        Ok(entry) => {
                            let _ = tx_paths.send(entry);
                        }
                        Err(ref e) => { return Err(format!("Skipped entry {entry:?}   Error: {e}")); }
                    }
                }
                Ok(())
            }));
        }

        drop(tx_paths);

        for _ in 0..num_workers {
            let rx_paths = rx_paths.clone();
            let (tx_out, rx_out) = bounded(num_workers);
            rx_out_receivers.push(rx_out);

            thread_handles.push(thread::spawn(move || -> std::result::Result<(), String> {
                for entry in rx_paths {
                    let archive_header;
                    let filepath_and_size;
                    //let sparse_segments; //fixme
                    // println!("{:?}", entry);
                    match Self::build_archive_header(&entry) {
                        Ok(values) => (archive_header, filepath_and_size/* , sparse_segments */) = values,
                        Err(e) => {
                            eprintln!("Skipped entry {}   - Reason: {e}", entry.path().display());
                            continue;
                        }
                    }

                    if let Some((filepath, mut file_size)) = filepath_and_size {
                        if let Ok(mut f_in) = File::open(&filepath) {
                            //println!("send fah {} {}", archive_header.len(), file_size);

                            // send header of file
                            // empty files (with length 0), must set last_chunk to true
                            let last_chunk = file_size == 0;
                            let _ = tx_out.send((archive_header, last_chunk));

                            // if file_size == 0 { continue; }
                            // fixme
                            // let seg_data_size: u64 = sparse_segments.data().map(|sd| sd.end - sd.start).sum();
                            // let mut data_size = if sparse_segments.is_empty() {
                            //     file_size
                            // } else {
                            //     seg_data_size
                            // };

                            // while data_size != 0 {
                            //     let buf_len = CHUNK_SIZE.min(usize::try_from(data_size).map_err(|e| e.to_string())?);
                            //     let mut buf_read = vec![0u8; buf_len];
                            // }


                            // read file and send its data
                            while file_size != 0 {
                                let buf_len = CHUNK_SIZE.min(usize::try_from(file_size).map_err(|e| e.to_string())?);
                                let mut buf_read = vec![0u8; buf_len];

                                f_in.read_exact(&mut buf_read).map_err(|e| e.to_string())?;
                                file_size -= buf_len as u64;

                                let last_chunk = file_size == 0;
                                let _ = tx_out.send((buf_read, last_chunk));
                                //println!("{:?} {} {} {}", filepath, file_size, buf_len, last_chunk);
                            }
                        } else {
                            eprintln!("Could not open - skipped: {}", filepath.display());
                            continue;
                        }
                    } else {
                        // send header of directory
                        //println!("send ah {}", archive_header.len());
                        let _ = tx_out.send((archive_header, true));
                    }
                }
                //println!("DONE"); // {}", rx_out_receivers.clone().len());
                // all entries done, send finish message
                //let _ = tx_out.send((Vec::new(), true));

                Ok(())
            }));
        }

        let buf_out = Vec::with_capacity(CHUNK_SIZE * 2);

        Self { thread_handles, rx_out_receivers, channel_index: None, channel_finished: vec![false; num_workers], buf_out }
    }

    #[allow(clippy::type_complexity)]
    fn build_archive_header(entry: &walkdir::DirEntry) -> Result<(Vec<u8>, Option<(PathBuf, u64)>/* , Vec<drill_press::Segment> */)> {
        // archive header initialized with place holder for header size
        let mut archive_header = vec![0u8; ARCHIVE_HEADER_LENGTH_SIZE];

        let entry_type = if entry.file_type().is_file() {
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

        let os_type = if cfg!(unix) { TYPE_UNIX } else { TYPE_WINDOWS };
        archive_header.push(os_type | entry_type);

        // path length and path (including filename)
        let path_string = entry.path().to_string_lossy();
        let path_len: u16 = path_string.len().try_into()?;
        archive_header.extend(path_len.to_le_bytes());
        archive_header.extend(path_string.as_bytes());

        // println!("{}", entry.path().display());

        // last access time 
        let time_accessed = entry.metadata()?.accessed()?.duration_since(UNIX_EPOCH)?.as_secs();
        archive_header.extend(time_accessed.to_le_bytes());
        // last modification time
        let time_modified = entry.metadata()?.modified()?.duration_since(UNIX_EPOCH)?.as_secs();
        archive_header.extend(time_modified.to_le_bytes());

        let mut file_size = 0;
        //let mut sparse_segments = vec![];
        if entry_type == TYPE_FILE {
            // file size
            file_size = entry.metadata()?.len();
            archive_header.extend(file_size.to_le_bytes());
            
            // get holes of sparse files
            //if file_size > 0 { // fixme
                // if let Ok(mut f_in) = File::open(&entry.path()) {
                //     sparse_segments = f_in.scan_chunks()?;

                //     archive_header.extend( u32::try_from(sparse_segments.holes().count())?.to_le_bytes() );

                //     for hole in sparse_segments.holes() {
                //         archive_header.extend(hole.start.to_le_bytes());
                //         archive_header.extend(hole.end.to_le_bytes());
                //     }
                // } else {
                //     // could not open file, add 0 holes   fixme: correct?
                //     archive_header.extend( 0u32.to_le_bytes() );
                // }
                // println!("{:?} {:?}", sparse_segments, entry.path());
            //}
        } else if entry_type == TYPE_SYMLINK_FILE || entry_type == TYPE_SYMLINK_DIR {
            // target path of symlink
            let target_path = fs::read_link(entry.path())?;
            let target_path_string = target_path.to_string_lossy();
            let target_path_len: u16 = target_path_string.len().try_into()?;
            archive_header.extend(target_path_len.to_le_bytes());
            archive_header.extend(target_path_string.as_bytes());
        }

        // permissions
        let mut perm: u16 = 0;
        if os_type == TYPE_UNIX && (entry_type == TYPE_FILE || entry_type == TYPE_DIRECTORY) {
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

        let mut filepath_and_size = None;
        if entry_type == TYPE_FILE {
            filepath_and_size = Some((entry.clone().into_path(), file_size));
        }

        Ok((archive_header, filepath_and_size/* , sparse_segments */))
    }
}

impl ReadChunk for ArchiveRead {
    fn read_chunk(&mut self) -> Result<(Vec<u8>, bool)> {
        while !self.channel_finished.iter().all(|x| *x) && self.buf_out.len() <= CHUNK_SIZE {
            // stay on same channel until last chunk of file using a blocking receive
            if let Some(channel_index) = self.channel_index
                && let Ok((data, last_chunk)) = self.rx_out_receivers[channel_index].recv()
            {
                //println!("cont recv, dat_len: {}, l {}", data.len(), last_chunk);
                self.buf_out.extend(data);
                if last_chunk {
                    self.channel_index = None;
                }
                continue; // check if there is already enough data in self.buf_out[]
            }

            let mut sel = Select::new();
            for rx in &self.rx_out_receivers {
                sel.recv(rx);
            }

            let sel_rdy_idx = sel.ready();
            //println!("sel_rdy_idx {}", sel_rdy_idx);
            match self.rx_out_receivers[sel_rdy_idx].try_recv() {
                Ok((data, last_chunk)) => {
                    // println!("recv {}, dat_len: {}, l {}", sel_rdy_idx, data.len(), last_chunk);
                    self.buf_out.extend(data);
                    if !last_chunk {
                        self.channel_index = Some(sel_rdy_idx);
                    }
                }
                Err(TryRecvError::Disconnected) => { self.channel_finished[sel_rdy_idx] = true; }
                Err(TryRecvError::Empty) => {}
            }
        }

        if self.buf_out.len() > CHUNK_SIZE {
            let chunk = self.buf_out.drain(..CHUNK_SIZE).collect();
            Ok((chunk, false))
        } else {
            // set final chunk flag
            Ok((self.buf_out.clone(), true))
        }
    }

    fn join_threads(&mut self) -> Result<()> {
        let thread_handles = mem::take(&mut self.thread_handles);
        for th in thread_handles {
            match th.join() {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(e.into()),
                Err(panic) => {
                    return Err(format!("ArchiveRead thread panicked: {:?}", panic).into());
                }
            }
        }
        Ok(())
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
    dir_times: HashMap<PathBuf, FileTimes>,
}

impl ArchiveWrite {
    pub fn new() -> Self {
        let buf_out = Vec::with_capacity(CHUNK_SIZE * 2);
        Self { f_out: None, buf_out, header_length: None, file_size: 0, file_times: FileTimes::new(), 
            file_path: PathBuf::new(), dir_times: HashMap::new() }
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
        // convert Windows path to unix path, if on unix (windows can handle unix path)
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

        let mut s;
        let mut e = 1;

        // entry's path
        let entry_path_string;
        (entry_path_string, e) = Self::get_path_from_header(header, e, created_on_os_type)?;
        let entry_path = PathBuf::from(&entry_path_string);

        println!("{}", entry_path.display());

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
            println!("D: {:?} {:?}", entry_path, self.file_times);

            // set timestamps of directory
            // if files will be added afterwards, the directory's original timestamps need to be set again
            if !File::open(&entry_path).is_ok_and(|dir| dir.set_times(self.file_times).is_ok()) {
                eprintln!("Could not set original timestamps for directory {}", entry_path.display());
            }

            self.dir_times.insert(entry_path.clone(), self.file_times);

        } else if file_type == TYPE_FILE {
            // create directory (of file), if it doesn't exists
            if let Some(dir) = &entry_path.parent() && !dir.exists() {
                println!("F: {:?}", dir);
                fs::create_dir_all(dir)?;
            }

            self.f_out = Some(File::create(&entry_path)?);

            // for error handling
            self.file_path = entry_path.clone();

            // file size
            s = e; e += size_of::<u64>();
            self.file_size = u64::from_le_bytes( header[s..e].try_into()? );
        } else if file_type == TYPE_SYMLINK_FILE || file_type == TYPE_SYMLINK_DIR {
            // create directory (of symlink), if it doesn't exists
            if let Some(dir) = &entry_path.parent() && !dir.exists() {
                println!("S: {:?}", dir);
                fs::create_dir_all(dir)?;
            }

            // symlink's target path
            let target_path;
            (target_path, e) = Self::get_path_from_header(header, e, created_on_os_type)?;

            // create symlink
            // remove it, if it already exists, otherwise symlink can't be created
            let _ = fs::remove_file(&entry_path);
            #[cfg(unix)]
            {
                std::os::unix::fs::symlink(&target_path, &entry_path)?;
            }
            #[cfg(windows)]
            {
                if file_type == TYPE_SYMLINK_FILE {
                    std::os::windows::fs::symlink_file(&target_path, &entry_path)?;
                }
                if file_type == TYPE_SYMLINK_DIR {
                    std::os::windows::fs::symlink_dir(&target_path, &entry_path)?;
                }
            }
            
            // set timestamps of symlink
            // replace with fs::set_times_nofollow() when in stable rust version
            if filetime::set_symlink_file_times(
                &entry_path,
                filetime::FileTime::from_system_time(time_accessed),    
                filetime::FileTime::from_system_time(time_modified)
            ).is_err() {
                eprintln!("Could not set original timestamps for symlink {}", entry_path.display());
            }
        } else {
            return Err(format!("Archive contains unknown file type: {file_type}").into());
        }

        // permissions
        // if this is a unix system and the archive was created on a unix system, set permission mode
        if cfg!(unix) && created_on_os_type == TYPE_UNIX && (file_type == TYPE_DIRECTORY || file_type == TYPE_FILE)
        {
            s = e; e += size_of::<u16>();
            let perm = u16::from_le_bytes(header[s..e].try_into()?);

            let fd = File::open(&entry_path)?;
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
                        eprintln!("Could not set original timestamps for file {}", self.file_path.display());
                    }
                    // as a new file was created, the file's parent directory would get the current timestamp, 
                    // but the original one is desired, therefore set original timestamp for the directory
                    if let Some(dir_path) = self.file_path.parent() 
                        && let Some(file_times) = self.dir_times.get(dir_path) {
                            if !File::open(dir_path).is_ok_and(|dir| dir.set_times(*file_times).is_ok()) {
                                eprintln!("Could not set original timestamps for directory {}", dir_path.display());
                            }
                    } else { /* do nothing */ }

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
