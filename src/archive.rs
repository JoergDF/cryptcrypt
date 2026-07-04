use std::fs::{self, File, FileTimes};
use std::io::{Read, Seek, Write};
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
use drill_press::{SegmentType, Segment, Segments, SparseFile};

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

/// Handles the reading and archiving of files/directories.
///
/// Walks the file system directory tree, processes files in parallel,
/// constructs archive headers, and serves the serialized archive stream in chunks.
pub struct ArchiveRead {
    /// Background worker thread handles running the directory walk and processing jobs.
    pub thread_handles: Vec<thread::JoinHandle<std::result::Result<(), String>>>,
    /// Channels receiving processed archive data blocks from the parallel worker threads.
    rx_out_receivers: Vec<Receiver<(Vec<u8>, bool)>>,
    /// Index of the active channel currently being read.
    channel_index: Option<usize>,
    /// Tracks which worker threads have finished processing their tasks.
    channel_finished: Vec<bool>,
    /// Accumulates output data to be served in uniform chunks of `CHUNK_SIZE`.
    buf_out: Vec<u8>,
}

impl ArchiveRead {
    /// Initializes the archive reading process by starting parallel worker threads.
    ///
    /// One worker thread walks the directory tree and sends discovered file entries and hard link
    /// information to a channel. Multiple worker threads then process these entries, build archive
    /// headers, read file contents, and send the formatted data to receivers.
    ///
    /// # Arguments
    /// - `f_in_path`: The root path of the directory tree to archive.
    ///
    /// # Returns
    /// - A new `ArchiveRead` instance.
    pub fn new(f_in_path: &Path) -> Self {
        let num_workers = num_cpus::get();
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
                        Err(ref e) => { eprintln!("Skipped entry while walking directory tree - Reason: {e}"); }
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
                    let sparse_segments;

                    match Self::build_archive_header(&entry, &hard_link_target) {
                        Ok(values) => (archive_header, filepath_and_size, sparse_segments) = values,
                        Err(e) => {
                            eprintln!("Skipped entry on building archive header for {} - Reason: {e}", entry.path().display());
                            continue;
                        }
                    }

                    if let Some((filepath, mut file_size)) = filepath_and_size {
                        match File::open(&filepath) {
                            Ok(mut f_in) => {
                                // send header of file
                                // empty files (with length 0), must set last_chunk to true
                                let last_chunk = file_size == 0;
                                let _ = tx_out.send((archive_header, last_chunk));

                                /// Helper function to read a chunk of data from a file up to the chunk limit.
                                ///
                                /// # Arguments
                                /// - `f_in`: File handle to read from.
                                /// - `data_size`: Total remaining data size to read.
                                ///
                                /// # Returns
                                /// - `Ok((buffer, remaining_size))` on success.
                                /// - `Err` on I/O or conversion error.
                                fn read_data(f_in: &mut File, mut data_size: u64) -> Result<(Vec<u8>, u64)> {
                                    let buf_len = CHUNK_SIZE.min(usize::try_from(data_size)?);
                                    let mut buf_read = vec![0u8; buf_len];
                                    f_in.read_exact(&mut buf_read)?;
                                    data_size -= buf_len as u64;
                                    Ok((buf_read, data_size))
                                }

                                if sparse_segments.is_empty() {
                                    // read file and send its data
                                    while file_size != 0 {
                                        let buf_read;
                                        (buf_read, file_size) = read_data(&mut f_in, file_size).map_err(|e| e.to_string())?;
                                        let last_chunk = file_size == 0;
                                        let _ = tx_out.send((buf_read, last_chunk));
                                    }
                                } else {
                                    // read/skip segments of a sparse file and send its data
                                    for (idx, seg) in sparse_segments.iter().enumerate() {
                                        let last_segment = (sparse_segments.len() - 1) == idx;
                                        if seg.is_data() {
                                            let mut seg_size = seg.len();
                                            while seg_size != 0 {
                                                let buf_read;
                                                (buf_read, seg_size) = read_data(&mut f_in, seg_size).map_err(|e| e.to_string())?;
                                                let last_chunk = seg_size == 0 && last_segment;
                                                let _ = tx_out.send((buf_read, last_chunk));
                                            }
                                        } else { // hole
                                            f_in.seek_relative(
                                                i64::try_from( seg.len() ).map_err(|e| e.to_string())? 
                                            ).map_err(|e| e.to_string())?;
                                            if last_segment {
                                                let _ = tx_out.send((vec![], true));
                                            }
                                        }
                                    }
                                }
                            },
                            Err(e) => {
                                eprintln!("Skipped entry on opening file {} - Reason: {e}", filepath.display());
                                continue;
                            },
                        }
                    } else {
                        // send header of entries without additional data
                        let _ = tx_out.send((archive_header, true));
                    }
                }

                Ok(())
            }));
        }

        let buf_out = Vec::with_capacity(CHUNK_SIZE * 2);

        Self { thread_handles, rx_out_receivers, channel_index: None, channel_finished: vec![false; num_workers], buf_out }
    }

    /// Appends the file path length and path string to the archive header buffer.
    ///
    /// # Arguments
    /// - `path`: The file system path to encode.
    /// - `archive_header`: The mutable buffer to append the encoded path to.
    ///
    /// # Returns
    /// - `Ok(())` on success.
    /// - `Err` if the path length exceeds `u16` capacity.
    fn add_path_to_header(path: &Path, archive_header: &mut Vec<u8>) -> Result<()> {
        // path length and path
        let path_string = path.to_string_lossy();
        let path_len: u16 = path_string.len().try_into()?;
        archive_header.extend(path_len.to_le_bytes());
        archive_header.extend(path_string.as_bytes());
        Ok(())
    }

    /// Builds the archive header bytes for a given file system entry.
    ///
    /// Creates a metadata block containing file type, path, timestamps, size,
    /// sparse segments (holes), and permissions.
    ///
    /// # Arguments
    /// - `entry`: The directory entry to construct the header for.
    /// - `hard_link_target`: Optional path pointing to the target if this is a hard link.
    ///
    /// # Returns
    /// - `Ok((archive_header, filepath_and_size, sparse_segments))` on success.
    /// - `Err` if metadata retrieval or OS-specific operations fail.
    #[allow(clippy::type_complexity)]
    fn build_archive_header(entry: &walkdir::DirEntry, hard_link_target: &Option<PathBuf>) -> Result<(Vec<u8>, Option<(PathBuf, u64)>, Vec<Segment>)> {
        // archive header initialized with place holder for header size
        let mut archive_header = vec![0u8; ARCHIVE_HEADER_LENGTH_SIZE];

        /// Computes and sets the final header size at the beginning of the header buffer.
        /// It is called after all other header fields have been added to the header buffer.
        ///
        /// # Arguments
        /// - `archive_header`: The mutable slice representing the archive header.
        ///
        /// # Returns
        /// - `Ok(())` on success.
        /// - `Err` if the header length cannot be converted to `u16`.
        fn set_header_size(archive_header: &mut [u8]) -> Result<()> {
            let header_size: [u8; ARCHIVE_HEADER_LENGTH_SIZE] =
                u16::try_from(archive_header.len() - ARCHIVE_HEADER_LENGTH_SIZE)?.to_le_bytes();
            archive_header[0] = header_size[0];
            archive_header[1] = header_size[1];
            Ok(())
        }

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
            return Err("Unsupported file type".into());
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
            set_header_size(&mut archive_header)?;

            return Ok((archive_header, None, vec![]));
        }

        // last access time 
        let time_accessed = entry.metadata()?.accessed()?.duration_since(UNIX_EPOCH)?.as_secs();
        archive_header.extend(time_accessed.to_le_bytes());
        // last modification time
        let time_modified = entry.metadata()?.modified()?.duration_since(UNIX_EPOCH)?.as_secs();
        archive_header.extend(time_modified.to_le_bytes());

        let mut file_size = 0;
        let mut sparse_segments = vec![];
        if entry_type == TYPE_FILE {
            // file size
            file_size = entry.metadata()?.len();
            archive_header.extend(file_size.to_le_bytes());

            // sparse file
            // if the files can be scanned for sparse parts, the holes are saved in the archive header
            if let Ok(mut f_in) = File::open(entry.path()) 
            && let Ok(segs) = f_in.scan_chunks() {
                sparse_segments = segs;            
                
                println!("arch: {}  {:?}", entry.path().display(), sparse_segments);

                // number of holes
                let holes_count = sparse_segments.holes().count();
                archive_header.extend(u16::try_from( holes_count )?.to_le_bytes());

                // start and end index of holes, if any
                for hole in sparse_segments.holes() {
                    // start and end are of type u64
                    archive_header.extend(hole.start.to_le_bytes());
                    archive_header.extend(hole.end.to_le_bytes());
                }
            }

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
        set_header_size(&mut archive_header)?;

        let mut filepath_and_size = None;
        if entry_type == TYPE_FILE {
            filepath_and_size = Some((entry.clone().into_path(), file_size));
        }

        Ok((archive_header, filepath_and_size, sparse_segments))
    }
}

impl ReadChunk for ArchiveRead {
    /// Reads a chunk of archived data, pulling from active worker channels.
    ///
    /// Polls channels from parallel workers and aggregates the data into `buf_out`.
    /// Returns chunks of `CHUNK_SIZE` until all threads finish and all data is read.
    ///
    /// # Returns
    /// - `Ok((chunk, last_chunk))` on success, where `last_chunk` is true if this is the final block.
    /// - `Err` on I/O or coordination error.
    fn read_chunk(&mut self) -> Result<(Vec<u8>, bool)> {
        while !self.channel_finished.iter().all(|x| *x) && self.buf_out.len() <= CHUNK_SIZE {
            // stay on same channel until last chunk of file using a blocking receive
            if let Some(channel_index) = self.channel_index
                && let Ok((data, last_chunk)) = self.rx_out_receivers[channel_index].recv()
            {
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
            match self.rx_out_receivers[sel_rdy_idx].try_recv() {
                Ok((data, last_chunk)) => {
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

    /// Joins all background worker threads and propagates any execution errors.
    ///
    /// # Returns
    /// - `Ok(())` if all threads exited successfully.
    /// - `Err` if any thread failed or panicked.
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

/// Handles extracting and writing archived entries back to the file system.
///
/// Decodes the incoming archive stream, creating files, directories, symlinks,
/// and hard links, restoring their permissions and timestamps.
#[derive(Default)]
pub struct ArchiveWrite {
    /// Active file handle for the entry currently being written.
    f_out: Option<File>,
    /// Internal buffer containing data received from the decryption stream.
    buf_out: Vec<u8>,
    /// Length of the header currently being processed.
    header_length: Option<usize>,
    /// Total bytes remaining to be written for the current file.
    file_size: u64,
    /// Timestamps (accessed, modified) of the current file being written.
    file_times: FileTimes,
    /// Path of the current file being written.
    file_path: PathBuf,
    /// List of directories and their original timestamps to be restored after extraction completes.
    dir_times: Vec<(PathBuf, SystemTime, SystemTime)>,
    /// List of pending hard link creations (target, link_path) to execute after extraction.
    pending_hardlinks: Vec<(PathBuf, PathBuf)>,
    /// Scanned sparse segments (data/hole) for the current sparse file.
    sparse_segments: Vec<Segment>,
    /// Index of the current sparse segment being written.
    sparse_segments_index: usize,
    /// Size in bytes of the current sparse data segment.
    data_segment_size: u64,
}

impl ArchiveWrite {
    /// Initializes a new, empty `ArchiveWrite` instance.
    ///
    /// # Returns
    /// - A default `ArchiveWrite` with allocated output buffer.
    pub fn new() -> Self {
        let buf_out = Vec::with_capacity(CHUNK_SIZE * 2);
        Self { f_out: None, buf_out, header_length: None, file_size: 0, file_times: FileTimes::new(), 
            file_path: PathBuf::new(), dir_times: vec![], pending_hardlinks: vec![], sparse_segments: vec![],
            sparse_segments_index: 0, data_segment_size: 0}
    }

    /// Ensures that the parent directory of the given path exists.
    ///
    /// Creates the parent directory recursively if it does not already exist.
    /// As parallel threads are used to create an archive, the sequence of entries differ from the
    /// sequence returned by walkdir, hence a file, etc. might show up before its directory was created.
    ///
    /// # Arguments
    /// - `entry_path`: The file system path whose parent directory should be created.
    ///
    /// # Returns
    /// - `Ok(())` on success.
    /// - `Err` on file system creation failure.
    fn create_parent_directory(entry_path: &Path) -> Result<()> {
        if let Some(dir) = entry_path.parent() && !dir.exists() {
            fs::create_dir_all(dir)?;
        }
        Ok(())
    }

    /// Parses a file path from the archive header slice.
    ///
    /// Reads the path length, extracts the path bytes, converts Windows path separators
    /// to Unix format if running on Unix, and returns the path string along with the new end index.
    ///
    /// # Arguments
    /// - `header`: The archive header bytes.
    /// - `current_end_index`: The starting index in the header to read from.
    /// - `created_on_os_type`: OS type flag indicating which system the archive was created on.
    ///
    /// # Returns
    /// - `Ok((parsed_path, next_index))` on success.
    /// - `Err` on parse or UTF-8 decoding failure.
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

    /// Configures a file as a sparse file on Windows.
    ///
    /// # Arguments
    /// - `file`: Reference to the file to set as sparse.
    ///
    /// # Returns
    /// - `Ok(())` on success.
    /// - `Err` if the system call fails.
    #[cfg(windows)]
    fn set_sparse_file_on_windows(file: &File) -> std::io::Result<()> {
        use std::os::windows::io::AsRawHandle;
        use winapi::um::ioapiset::DeviceIoControl;
        use winapi::um::winioctl::FSCTL_SET_SPARSE;

        let handle = file.as_raw_handle();
        let mut bytes_returned = 0;
        unsafe {
            let result = DeviceIoControl(
                handle as _,
                FSCTL_SET_SPARSE,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                0,
                &mut bytes_returned,
                std::ptr::null_mut(),
            );

            if result == 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok(())
    }

    /// Evaluates a parsed archive header to create the corresponding file system entry.
    ///
    /// Handles directories, files (including sparse configuration), symlinks, and hard links.
    /// Sets file size, times, and system-level permissions depending on OS.
    ///
    /// # Arguments
    /// - `header`: The raw header bytes.
    ///
    /// # Returns
    /// - `Ok(())` on success.
    /// - `Err` on creation, I/O, or permission errors.
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
            return Ok(());
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

            // create file
            self.f_out = Some(File::create(&entry_path)?);

            // for printing errors
            self.file_path = entry_path.clone();

            // file size
            s = e; e += size_of::<u64>();
            self.file_size = u64::from_le_bytes( header[s..e].try_into()? );

            // holes of a sparse file
            s = e; e += size_of::<u16>();
            let holes_count = u16::from_le_bytes( header[s..e].try_into()? );

            if holes_count > 0 {
                // restore data- and hole-segments of sparse file
                let mut data_start = 0;
                for _ in 0..holes_count {
                    s = e; e += size_of::<u64>();
                    let hole_start = u64::from_le_bytes( header[s..e].try_into()? );
                    s = e; e += size_of::<u64>();
                    let hole_end = u64::from_le_bytes( header[s..e].try_into()? );

                    if hole_start != 0 {
                        // if first segment is not a hole, add a data segment
                        self.sparse_segments.push( Segment { segment_type: SegmentType::Data, range: data_start..hole_start} );
                    }
                    self.sparse_segments.push( Segment { segment_type: SegmentType::Hole, range: hole_start..hole_end } );
                    data_start = hole_end;
                }
                // if last segment is not a hole, add a data segment
                if data_start != self.file_size {
                    self.sparse_segments.push( Segment { segment_type: SegmentType::Data, range: data_start..self.file_size} );
                }
                println!("unar: {:?} {:?}", entry_path.display(), self.sparse_segments);

                // Windows requires to set sparse flag for a sparse file
                #[cfg(windows)]
                Self::set_sparse_file_on_windows(self.f_out.as_ref().unwrap())?;
            }
            
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
    /// Processes incoming stream data and writes it to the current active file.
    ///
    /// Handles headers to initialize files, parses sparse segments, and writes
    /// data chunks. Performs physical file creation and metadata restoration.
    ///
    /// # Arguments
    /// - `buf_in`: Raw input byte slice.
    ///
    /// # Returns
    /// - `Ok(())` on success.
    /// - `Err` on writing, seeking, or parsing failure.
    fn write_files(&mut self, buf_in: &[u8]) -> Result<()> {
        self.buf_out.extend(buf_in);

        loop {
            if let Some(mut f_out) = self.f_out.as_ref() {
                // Local helper closure to write buffered data to file
                let mut write_data = |f_out_size: u64| -> Result<u64> {
                    let data_size = self.buf_out.len().min(f_out_size.try_into()?);
                    let buf_out_slice: Vec<u8> = self.buf_out.drain(..data_size).collect();
                    f_out.write_all(&buf_out_slice)?;
                    Ok(data_size as u64)
                };

                if self.sparse_segments.is_empty() {
                    // write non-sparse file
                    let write_size = write_data(self.file_size)?;
                    self.file_size -= write_size;
                    if self.buf_out.is_empty() {
                        break;
                    }
                } else {
                    // write sparse file
                    let segment = &self.sparse_segments[self.sparse_segments_index];

                    match segment.segment_type {
                        SegmentType::Data => {
                            if self.data_segment_size == 0 {
                                self.data_segment_size = segment.len();
                            }
                            
                            let write_size = write_data(self.data_segment_size)?;
                            self.data_segment_size -= write_size;
                            self.file_size -= write_size;
                            if self.data_segment_size == 0 {
                                self.sparse_segments_index += 1;
                            }
                        }
                        SegmentType::Hole => {
                            f_out.seek_relative((segment.len() - 1).try_into()?)?;
                            f_out.write_all(&[0])?;
                            self.file_size -= segment.len();
                            self.sparse_segments_index += 1;
                        }
                    }

                    if self.file_size == 0 {
                        // holes must not be set before the whole file was written
                        for hole in self.sparse_segments.holes() {
                            f_out.drill_hole(hole.start, hole.end)?;
                        }

                        self.data_segment_size = 0;
                        self.sparse_segments_index = 0;
                        self.sparse_segments.clear();
                    }

                    // no data left and no hole as next segment
                    if self.buf_out.is_empty() 
                    && self.sparse_segments_index < self.sparse_segments.len()
                    && self.sparse_segments[self.sparse_segments_index].segment_type != SegmentType::Hole {
                        break;
                    }
                }

                if self.file_size == 0 {
                    // set file times after all data has been written
                    if f_out.set_times(self.file_times).is_err() {
                        eprintln!("Could not set original timestamps for file {}", self.file_path.display());
                    }
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

    /// Finalizes the extraction process by completing delayed operations.
    ///
    /// Creates any pending hard links and restores directory timestamps. These operations
    /// are deferred until the end of extraction to prevent sub-file creations from altering parent
    /// directory timestamps.
    ///
    /// # Returns
    /// - `Ok(())` on success.
    /// - `Err` if hard link creation or timestamp updates fail.
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
            // supports Windows and Unix
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



// ======================================================================
// Unit tests
// ======================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::path::{Path, PathBuf};
    use std::time::UNIX_EPOCH;

    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new(dirname: &str) -> Self {
            let path = PathBuf::from(dirname);
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn test_add_path_to_header() {
        let mut buf = Vec::new();
        ArchiveRead::add_path_to_header(Path::new("hello/world.txt"), &mut buf).unwrap();
        
        // Path length should be 15 (2 bytes, little-endian)
        let expected_len = 15u16.to_le_bytes();
        assert_eq!(buf[0..2], expected_len);
        assert_eq!(&buf[2..], b"hello/world.txt");
    }

    #[test]
    fn test_create_parent_directory() {
        let temp_dir = TestDir::new("test_archive_create_parent_dir");
        let nested_file = temp_dir.path.join("a/b/c/file.txt");
        assert!(!nested_file.parent().unwrap().exists());
        
        ArchiveWrite::create_parent_directory(&nested_file).unwrap();
        assert!(nested_file.parent().unwrap().exists());

        let nested_file2 = temp_dir.path.join("a/b/c/file2.txt");
        assert!(nested_file2.parent().unwrap().exists());
        ArchiveWrite::create_parent_directory(&nested_file2).unwrap();
        assert!(nested_file2.parent().unwrap().exists());
    }

    #[test]
    fn test_get_path_from_header() {
        // Test standard unix path decoding
        let mut header = Vec::new();
        let path_str = "foo/bar/baz.txt";
        let path_len = path_str.len() as u16;
        header.extend_from_slice(&path_len.to_le_bytes());
        header.extend_from_slice(path_str.as_bytes());

        let (decoded, end_idx) = ArchiveWrite::get_path_from_header(&header, 0, TYPE_UNIX).unwrap();
        assert_eq!(decoded, "foo/bar/baz.txt");
        assert_eq!(end_idx, header.len());

        // Test Windows path on Unix system decoding conversion
        let mut header_win = Vec::new();
        let path_str_win = "foo\\bar\\baz.txt";
        let path_len_win = path_str_win.len() as u16;
        header_win.extend_from_slice(&path_len_win.to_le_bytes());
        header_win.extend_from_slice(path_str_win.as_bytes());

        let (decoded_win, end_idx_win) = ArchiveWrite::get_path_from_header(&header_win, 0, TYPE_WINDOWS).unwrap();
        if cfg!(unix) {
            assert_eq!(decoded_win, "foo/bar/baz.txt");
        } else {
            assert_eq!(decoded_win, "foo\\bar\\baz.txt");
        }
        assert_eq!(end_idx_win, header_win.len());
    }

    #[test]
    fn test_archive_read_write() {
        let src_dir = TestDir::new("test_archive_src");

        // Create standard folder and file
        let file1_path = src_dir.path.join("file1.txt");
        let content1 = b"Hello from file 1!";
        fs::write(&file1_path, content1).unwrap();

        // Create empty file
        let empty_file_path = src_dir.path.join("empty.txt");
        fs::write(&empty_file_path, b"").unwrap();

        // Create nested folder and file
        let sub_dir = src_dir.path.join("subdir");
        fs::create_dir(&sub_dir).unwrap();
        let file2_path = sub_dir.join("file2.bin");
        let content2 = vec![0xAA; 5000];
        fs::write(&file2_path, &content2).unwrap();

        // Create sparse file
        let sparse_path = src_dir.path.join("sparse.bin");
        {
            let mut f = File::create(&sparse_path).unwrap();

            #[cfg(windows)]
            ArchiveWrite::set_sparse_file_on_windows(&f).unwrap();

            // Write 64KB of data at start
            let start_data = vec![1u8; 65536];
            f.write_all(&start_data).unwrap();

            // Seek to 128KB and write 64KB of data at end (grows the file to 192KB)
            f.seek(SeekFrom::Start(131072)).unwrap();

            let end_data = vec![2u8; 65536];
            f.write_all(&end_data).unwrap();

            // Explicitly punch the hole in the middle region (64KB to 128KB)
            f.drill_hole(65536, 131072).unwrap();
        }

        // Create symlink (windows and unix) and hardlink (Unix only)
        let symlink_path = src_dir.path.join("link.txt");
        #[cfg(unix)]
        let hardlink_path = src_dir.path.join("hardlink.txt");
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("file1.txt", &symlink_path).unwrap();
            fs::hard_link(&file1_path, &hardlink_path).unwrap();
        }
        #[cfg(windows)]
        {
            std::os::windows::fs::symlink_file("file1.txt", &symlink_path).unwrap();
        }

        // Get original modified time of file1
        let meta_orig1 = fs::metadata(&file1_path).unwrap();
        let modified_orig1 = meta_orig1.modified().unwrap();

        // Get original modified time of subdirectory
        let meta_orig2 = fs::metadata(&sub_dir).unwrap();
        let modified_orig2 = meta_orig2.modified().unwrap();

        // Perform archiving using ArchiveRead
        let mut reader = ArchiveRead::new(&src_dir.path);
        let mut archive_bytes = Vec::new();
        for i in 0..=128 {
            let (chunk, last) = reader.read_chunk().unwrap();
            archive_bytes.extend(&chunk);
            if last {
                break;
            }
            assert!(i < 128); // timeout not reached
        }
        
        reader.join_threads().unwrap();

        // Verify we got some archive bytes
        assert!(!archive_bytes.is_empty());

        // Delete the original files before extracting to verify recreation
        fs::remove_dir_all(&src_dir.path).unwrap();
        assert!(!src_dir.path.exists());

        // Perform extraction using ArchiveWrite by feeding it in small chunks
        let mut writer = ArchiveWrite::new();
        for chunk in archive_bytes.chunks(100) {
            writer.write_files(chunk).unwrap();
        }
        writer.write_others().unwrap();

        // Verify structure is fully recreated
        assert!(src_dir.path.exists());
        assert!(file1_path.exists());
        assert!(empty_file_path.exists());
        assert!(sub_dir.exists());
        assert!(file2_path.exists());
        assert!(sparse_path.exists());

        // Verify contents
        assert_eq!(fs::read(&file1_path).unwrap(), content1);
        assert_eq!(fs::read(&empty_file_path).unwrap(), b"");
        assert_eq!(fs::read(&file2_path).unwrap(), content2);

        // Verify sparse file content
        {
            let mut f = File::open(&sparse_path).unwrap();
            let mut start_buf = vec![0; 65536];
            f.read_exact(&mut start_buf).unwrap();
            assert_eq!(start_buf, vec![1u8; 65536]);

            f.seek(SeekFrom::Start(131072)).unwrap();
            let mut end_buf = vec![0; 65536];
            f.read_exact(&mut end_buf).unwrap();
            assert_eq!(end_buf, vec![2u8; 65536]);

            assert_eq!(fs::metadata(&sparse_path).unwrap().len(), 196608);

            // Verify it is actually a sparse file (has 1 hole)
            let segs = f.scan_chunks().unwrap();
            assert_eq!(segs.holes().count(), 1);
            let hole = segs.holes().next().unwrap();
            assert_eq!(hole.start, 65536);
            assert_eq!(hole.end, 131072);
        }

        // Verify modified time of file1 is restored (seconds precision)
        let meta_restored1 = fs::metadata(&file1_path).unwrap();
        let modified_restored1 = meta_restored1.modified().unwrap();
        assert_eq!(
            modified_orig1.duration_since(UNIX_EPOCH).unwrap().as_secs(),
            modified_restored1.duration_since(UNIX_EPOCH).unwrap().as_secs()
        );

        // Verify modified time of subdir is restored (seconds precision)
        let meta_restored2 = fs::metadata(&sub_dir).unwrap();
        let modified_restored2 = meta_restored2.modified().unwrap();
        assert_eq!(
            modified_orig2.duration_since(UNIX_EPOCH).unwrap().as_secs(),
            modified_restored2.duration_since(UNIX_EPOCH).unwrap().as_secs()
        );

        // Verify symlink
        assert!(symlink_path.exists());
        let symlink_metadata = fs::symlink_metadata(&symlink_path).unwrap();
        assert!(symlink_metadata.file_type().is_symlink());
        let target = fs::read_link(&symlink_path).unwrap();
        assert_eq!(target, Path::new("file1.txt"));
        
        // Verify hardlink (Unix only)
        #[cfg(unix)]
        {
            assert!(hardlink_path.exists());
            use std::os::unix::fs::MetadataExt;
            let meta_f1 = fs::metadata(&file1_path).unwrap();
            let meta_hl = fs::metadata(&hardlink_path).unwrap();
            assert_eq!(meta_f1.ino(), meta_hl.ino());
        }
    }

   #[test]
    fn test_archive_sparse_files() {
        let src_dir = TestDir::new("test_archive_sparse");

        // hole only
        let hole_filepath = src_dir.path.join("hole.bin");
        let mut hole_file = File::create(&hole_filepath).unwrap();
        let hole_filesize = 131072;
        #[cfg(windows)]
        ArchiveWrite::set_sparse_file_on_windows(&hole_file).unwrap();
        hole_file.seek(SeekFrom::Start(hole_filesize - 1)).unwrap();
        hole_file.write_all(&[0]).unwrap();
        hole_file.drill_hole(0, hole_filesize).unwrap();
        hole_file.sync_all().unwrap();

        // hole-data
        let hole_data_filepath = src_dir.path.join("hole_data.bin");
        let mut hole_data_file = File::create(&hole_data_filepath).unwrap();
        #[cfg(windows)]
        ArchiveWrite::set_sparse_file_on_windows(&hole_data_file).unwrap();
        hole_data_file.seek_relative(65536).unwrap();
        hole_data_file.write_all(&[0x0Du8; 256]).unwrap();
        hole_data_file.drill_hole(0, 65536).unwrap();
        hole_data_file.sync_all().unwrap();

        // data-hole
        let data_hole_filepath = src_dir.path.join("data_hole.bin");
        let mut data_hole_file = File::create(&data_hole_filepath).unwrap();
        #[cfg(windows)]
        ArchiveWrite::set_sparse_file_on_windows(&data_hole_file).unwrap();
        data_hole_file.write_all(&vec![0xD0u8; 131072]).unwrap();
        data_hole_file.seek_relative(131072 - 1).unwrap();
        data_hole_file.write_all(&[0]).unwrap();
        data_hole_file.drill_hole(131072, 131072 + 131072).unwrap();
        data_hole_file.sync_all().unwrap();

        // hole-data-hole
        let hdh_filepath = src_dir.path.join("hole_data_hole.bin");
        let mut hdh_file = File::create(&hdh_filepath).unwrap();
        #[cfg(windows)]
        ArchiveWrite::set_sparse_file_on_windows(&hdh_file).unwrap();
        hdh_file.seek_relative(CHUNK_SIZE as i64).unwrap();
        hdh_file.write_all(&vec![3; CHUNK_SIZE]).unwrap();
        hdh_file.seek_relative(CHUNK_SIZE as i64 - 1).unwrap();
        hdh_file.write_all(&[0]).unwrap();
        hdh_file.drill_hole(0, CHUNK_SIZE as u64).unwrap();
        hdh_file.drill_hole(2 * CHUNK_SIZE as u64, 3 * CHUNK_SIZE as u64).unwrap();
        hdh_file.sync_all().unwrap();


        // Perform archiving using ArchiveRead
        let mut reader = ArchiveRead::new(&src_dir.path);
        let mut archive_bytes = Vec::new();
        for i in 0..=128 {
            let (chunk, last_chunk) = reader.read_chunk().unwrap();
            archive_bytes.extend(&chunk);
            if last_chunk { break; }
            assert!(i < 128); // timeout not reached
        }
        reader.join_threads().unwrap();

        // Verify we got some archive bytes
        assert!(!archive_bytes.is_empty());

        // Delete the original files before extracting to verify recreation
        fs::remove_dir_all(&src_dir.path).unwrap();
        assert!(!src_dir.path.exists());


        // Perform extraction using ArchiveWrite
        let mut writer = ArchiveWrite::new();
        for chunk in archive_bytes.chunks(CHUNK_SIZE) {
            writer.write_files(chunk).unwrap();
        }
        writer.write_others().unwrap();

        // Verify structure is fully recreated
        assert!(src_dir.path.exists());
        assert!(hole_filepath.exists());
        assert!(hole_data_filepath.exists());
        assert!(data_hole_filepath.exists());


        // Verify hole-only file
        let mut hole_file = File::open(&hole_filepath).unwrap();
        let segs = hole_file.scan_chunks().unwrap();
        assert_eq!(segs.len(), 1);
        assert_eq!(segs.holes().count(), 1);
        assert_eq!(segs.data().count(), 0);
        let hole = segs.first().unwrap();
        assert_eq!(hole.segment_type, SegmentType::Hole);
        assert_eq!(hole.range.start, 0);
        assert_eq!(hole.range.end, hole_filesize);

        // Verify hole-data file
        let mut hole_data_file = File::open(&hole_data_filepath).unwrap();
        let segs = hole_data_file.scan_chunks().unwrap();
        assert_eq!(segs.len(), 2);
        assert_eq!(segs.holes().count(), 1);
        assert_eq!(segs.data().count(), 1);
        let hole = segs.first().unwrap();   // check hole-segment
        assert_eq!(hole.segment_type, SegmentType::Hole);
        assert_eq!(hole.range.start, 0);
        assert_eq!(hole.range.end, 65536);
        let data = segs.last().unwrap();    // check data-segment
        assert_eq!(data.segment_type, SegmentType::Data);
        assert_eq!(data.range.start, 65536);
        assert_eq!(data.range.end, 65536 + 256);
        hole_data_file.rewind().unwrap();             // check file contents
        let mut buf = vec![];
        let file_size = hole_data_file.read_to_end(&mut buf).unwrap();
        assert_eq!(file_size, 65536 + 256);
        assert_eq!(buf[..65536], vec![0; 65536]);
        assert_eq!(buf[65536..], vec![0x0Du8; 256]);
        
        // Verify data-hole file
        let mut data_hole_file = File::open(&data_hole_filepath).unwrap();
        let segs = data_hole_file.scan_chunks().unwrap();
        assert_eq!(segs.len(), 2);
        assert_eq!(segs.holes().count(), 1);
        assert_eq!(segs.data().count(), 1);
        let data = segs.first().unwrap();   // check data-segment
        assert_eq!(data.segment_type, SegmentType::Data);
        assert_eq!(data.range.start, 0);
        assert_eq!(data.range.end, 131072); 
        let hole = segs.last().unwrap();    // check hole-segment
        assert_eq!(hole.segment_type, SegmentType::Hole);
        assert_eq!(hole.range.start, 131072);
        assert_eq!(hole.range.end, 131072 + 131072);
        data_hole_file.rewind().unwrap();             // check file contents
        let mut buf = vec![];
        let file_size = data_hole_file.read_to_end(&mut buf).unwrap();
        assert_eq!(file_size, 131072 + 131072);
        assert_eq!(buf[..131072], vec![0xD0u8; 131072]);
        assert_eq!(buf[131072..], vec![0; 131072]);

        // Verify hole-data-hole file
        let mut hdh_file = File::open(&hdh_filepath).unwrap();
        let segs = hdh_file.scan_chunks().unwrap();
        assert_eq!(segs.len(), 3);
        assert_eq!(segs.holes().count(), 2);
        assert_eq!(segs.data().count(), 1);
        let hole = segs.first().unwrap();   // check hole-segment
        assert_eq!(hole.segment_type, SegmentType::Hole);
        assert_eq!(hole.range.start, 0);
        assert_eq!(hole.range.end, CHUNK_SIZE as u64);
        let data = segs.get(1).unwrap(); // check data-segment
        assert_eq!(data.segment_type, SegmentType::Data);
        assert_eq!(data.range.start, CHUNK_SIZE as u64);
        assert_eq!(data.range.end, 2 * CHUNK_SIZE as u64); 
        let hole = segs.last().unwrap();    // check hole-segment
        assert_eq!(hole.segment_type, SegmentType::Hole);
        assert_eq!(hole.range.start, 2 * CHUNK_SIZE as u64);
        assert_eq!(hole.range.end, 3 * CHUNK_SIZE as u64);
        hdh_file.rewind().unwrap();                   // check file contents
        let mut buf = vec![];
        let file_size = hdh_file.read_to_end(&mut buf).unwrap();
        assert_eq!(file_size, 3 * CHUNK_SIZE);
        assert_eq!(buf[..CHUNK_SIZE], vec![0; CHUNK_SIZE]);
        assert_eq!(buf[CHUNK_SIZE..2 * CHUNK_SIZE], vec![3; CHUNK_SIZE]);
        assert_eq!(buf[2 * CHUNK_SIZE..], vec![0; CHUNK_SIZE]);
    }


    #[test]
    fn test_archive_nonexistent_dir() {
        let mut reader = ArchiveRead::new(Path::new("test_archive_does_not_exist"));
        let (chunk, last) = reader.read_chunk().unwrap();
        assert!(last);
        assert!(chunk.is_empty());
        reader.join_threads().unwrap();
    }

    #[test]
    fn test_archive_empty_dir() {
        let src_dir = TestDir::new("test_archive_empty");
        
        let mut reader = ArchiveRead::new(&src_dir.path);
        let mut archive_bytes = Vec::new();

        let (chunk, last) = reader.read_chunk().unwrap();
        archive_bytes.extend(&chunk);
        assert!(last);

        reader.join_threads().unwrap();

        // Delete source
        fs::remove_dir_all(&src_dir.path).unwrap();

        // Extract
        let mut writer = ArchiveWrite::new();
        writer.write_files(&archive_bytes).unwrap();
        writer.write_others().unwrap();

        // Recreated directory should exist and be empty
        assert!(src_dir.path.exists());
        let count = fs::read_dir(&src_dir.path).unwrap().count();
        assert_eq!(count, 0);
    }
}

