use std::fs::{self, File, FileTimes};
use std::io::{Read, Write};
use std::mem::{self, size_of};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use typed_path::Utf8WindowsPath;
use walkdir::WalkDir;
use crossbeam_channel::{Receiver, Select, TryRecvError, bounded};
use num_cpus;
use filetime;
#[cfg(unix)]
use std::collections::HashMap;
//use drill_press::{Segments, SparseFile};

use crate::common_io::{ReadChunk, WriteFiles};
use crate::{CHUNK_SIZE, Result};


const TYPE_FILE:         u8 = 0x00;
const TYPE_DIRECTORY:    u8 = 0x01;
const TYPE_SYMLINK_FILE: u8 = 0x02;
const TYPE_SYMLINK_DIR:  u8 = 0x03;
const TYPE_HARDLINK:     u8 = 0x04;
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
                #[cfg(unix)]
                let mut hard_link_files: HashMap<u64, PathBuf> = HashMap::new();

                for entry in WalkDir::new(f_in_path) {
                    match entry {
                        Ok(entry) => {
                            // check if entry is a hard link
                            #[cfg(unix)]
                            {
                                use std::os::unix::fs::MetadataExt;
                                use walkdir::DirEntryExt;
                                
                                let mut hard_link_target: Option<PathBuf> = None;
                                if entry.file_type().is_file() 
                                    && let Ok(meta) = entry.metadata() && meta.nlink() > 1 {
                                        let file_id = entry.ino();
                                        if let Some(hl_target) = hard_link_files.get(&file_id) {
                                            // entry is hard link
                                            hard_link_target = Some(hl_target.to_owned());
                                        } else {
                                            // entry is taken as original file path (i.e. target of hard link)
                                            hard_link_files.insert(file_id, entry.clone().into_path());
                                        }
                                }
                                let _ = tx_paths.send((entry, hard_link_target));
                            }
                            #[cfg(windows)]
                            let _ = tx_paths.send((entry, None));
                            // windows: use number_of_links() and file_index() of std::os::windows::fs::MetadataExt, when supported by stable rust
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
                for (entry, hard_link_target) in rx_paths {
                    let archive_header;
                    let filepath_and_size;
                    //let sparse_segments; //fixme
                    // println!("{:?}", entry);
                    match Self::build_archive_header(&entry, &hard_link_target) {
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
                        // send header of entries without additional data
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

    fn add_path_to_header(path: &Path, archive_header: &mut Vec<u8>) -> Result<()> {
        // path length and path 
        let path_string = path.to_string_lossy();
        let path_len: u16 = path_string.len().try_into()?;
        archive_header.extend(path_len.to_le_bytes());
        archive_header.extend(path_string.as_bytes());
        Ok(())
    }

    #[allow(clippy::type_complexity)]
    fn build_archive_header(entry: &walkdir::DirEntry, hard_link_target: &Option<PathBuf>) -> Result<(Vec<u8>, Option<(PathBuf, u64)>/* , Vec<drill_press::Segment> */)> {
        // archive header initialized with place holder for header size
        let mut archive_header = vec![0u8; ARCHIVE_HEADER_LENGTH_SIZE];

        let entry_type = if hard_link_target.is_some() {
            TYPE_HARDLINK
        } else if entry.file_type().is_file() {
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
        Self::add_path_to_header(entry.path(), &mut archive_header)?;

        // println!("{}", entry.path().display());

        if entry_type == TYPE_HARDLINK {
            
            // target path of hard link
            let target_path = hard_link_target.as_ref().unwrap();
            Self::add_path_to_header(target_path, &mut archive_header)?;

            // header size
            let header_size: [u8; ARCHIVE_HEADER_LENGTH_SIZE] = u16::try_from(
                archive_header.len() - ARCHIVE_HEADER_LENGTH_SIZE)?.to_le_bytes();
            archive_header[0] = header_size[0];
            archive_header[1] = header_size[1];

            return Ok((archive_header, None))
        }

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
            Self::add_path_to_header(&target_path, &mut archive_header)?;
        }

        // permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            
            let mut perm: u16 = 0;
            if entry_type == TYPE_FILE || entry_type == TYPE_DIRECTORY {
                let permission_mode = entry.metadata()?.permissions().mode();
                // use 12 least significant bits
                perm = (permission_mode & 0x0FFF) as u16;
            }
            archive_header.extend(perm.to_le_bytes());
        }
        #[cfg(windows)]
        {
           archive_header.extend(0u16.to_le_bytes());
        }

        // header size
        let header_size: [u8; ARCHIVE_HEADER_LENGTH_SIZE] = u16::try_from(
            archive_header.len() - ARCHIVE_HEADER_LENGTH_SIZE)?.to_le_bytes();
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
    dir_times: Vec<(PathBuf, SystemTime, SystemTime)>,
    pending_hardlinks: Vec<(PathBuf, PathBuf)>,
}

impl ArchiveWrite {
    pub fn new() -> Self {
        let buf_out = Vec::with_capacity(CHUNK_SIZE * 2);
        Self { f_out: None, buf_out, header_length: None, file_size: 0, file_times: FileTimes::new(), 
            file_path: PathBuf::new(), dir_times: vec![], pending_hardlinks: vec![] }
    }

    fn create_parent_directory(entry_path: &Path) -> Result<()> {
        // create directory, if it doesn't exists
        // as parallel threads are used to create an archive, the sequence of entries differ from the sequence returned be walkdir
        // hence a file, etc. might show up before its directory was created
        if let Some(dir) = entry_path.parent() && !dir.exists() {
            fs::create_dir_all(dir)?;
        }
        Ok(())
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

        // println!("{}", entry_path.display());

        if file_type == TYPE_HARDLINK {
            // hard link's target path
            let target_path;
            (target_path, _) = Self::get_path_from_header(header, e, created_on_os_type)?;
            
            self.pending_hardlinks.push((PathBuf::from(target_path), entry_path));
            return Ok(())
        }

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
            // create directory 
            // it could be an empty one therefore it would not be created by other entries
            fs::create_dir_all(&entry_path)?;

            // save timestamps for restoring them at the end
            self.dir_times.push((entry_path.clone(), time_accessed, time_modified));

        } else if file_type == TYPE_FILE {
            // create directory (of file), if it doesn't exists
            Self::create_parent_directory(&entry_path)?;

            self.f_out = Some(File::create(&entry_path)?);

            // for error handling
            self.file_path = entry_path.clone();

            // file size
            s = e; e += size_of::<u64>();
            self.file_size = u64::from_le_bytes( header[s..e].try_into()? );

        } else if file_type == TYPE_SYMLINK_FILE || file_type == TYPE_SYMLINK_DIR {
            // create directory (of symlink), if it doesn't exists
            Self::create_parent_directory(&entry_path)?;

            // symlink's target path
            let target_path;
            (target_path, e) = Self::get_path_from_header(header, e, created_on_os_type)?;

            // remove symlink, if it already exists, otherwise it can't be created
            let _ = fs::remove_file(&entry_path);

            // create symlink
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
            // replace with fs::set_times_nofollow() when stable rust version supports it
            match filetime::set_symlink_file_times(
                &entry_path,
                filetime::FileTime::from_system_time(time_accessed),    
                filetime::FileTime::from_system_time(time_modified)
            ) {
                Ok(()) => {},
                Err(e) => eprintln!("Could not set original timestamps for symlink {}: {e}", entry_path.display()),
            }
        } else {
            return Err(format!("Archive contains unknown file type: {file_type}").into());
        }

        // permissions
        // if this is a unix system and the archive was created on a unix system, set permission mode
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            if created_on_os_type == TYPE_UNIX && (file_type == TYPE_DIRECTORY || file_type == TYPE_FILE) {
                s = e; e += size_of::<u16>();
                let perm = u16::from_le_bytes(header[s..e].try_into()?);

                let fd = File::open(&entry_path)?;
                let mut permissions = fd.metadata()?.permissions();
                let mode_masked = permissions.mode() & 0xFFFF_F000;
                permissions.set_mode(mode_masked | u32::from(perm & 0x0FFF));
                fd.set_permissions(permissions)?;
            }
        }
        #[cfg(windows)]
        {
            // keep compiler quiet
            s = e; e += size_of::<u16>();
            let _perm = u16::from_le_bytes(header[s..e].try_into()?);
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

    fn write_others(&self) -> Result<()> {
        // create hard links, if there are any
        for (target_path, entry_path) in &self.pending_hardlinks {
            // create directory (of hard link), if it doesn't exists
            Self::create_parent_directory(entry_path)?;

            // remove hard link, if it already exists, otherwise it can't be created
            let _ = fs::remove_file(entry_path);

            fs::hard_link(target_path, entry_path)?;
        }

        // set timestamps of directories
        // need to be done after all elements have been created, as creation of an element 
        // updates timestamp of its parent directory to now
        for (dir_path, atime, mtime) in &self.dir_times {
            match filetime::set_file_times(
                dir_path,
                filetime::FileTime::from_system_time(*atime),    
                filetime::FileTime::from_system_time(*mtime)
            ) {
                Ok(()) => {},
                Err(e) => eprintln!("Could not set original timestamps for directory {}: {e}", dir_path.display()),
            };
        }

        Ok(())
    }
}
