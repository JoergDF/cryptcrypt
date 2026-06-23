use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::thread;
use crossbeam_channel::{bounded, Sender, Receiver};
use secrecy::SecretSlice;
use std::collections::HashMap;
use num_cpus;

use crate::{AES_NONCE_SIZE, AES_TAG_SIZE, CHA_NONCE_SIZE, CHA_TAG_SIZE, Result, SPLIT_ENC_FILE_EXT};


pub trait ReadChunk {
    fn read_chunk(&mut self) -> Result<(Vec<u8>, bool)>;
    fn join_threads(&mut self) -> Result<()>;
}

pub trait WriteFiles {
    fn write_files(&mut self, buf_in: &[u8]) -> Result<()>;
}

/// Struct for file input
pub struct ReadInput {
    /// Input file to read data from
    f_in: File, 
    /// Path of input file
    f_in_path: PathBuf,
    /// Total size in bytes of input data (over all optional splits) remaining to be read
    f_in_total_size_remaining: u64,
    /// Size in bytes of each chunk to process per iteration
    chunk_size: usize,
    /// List of split sizes for input
    f_in_split: Vec<u64>,    
    /// Index into split list
    split_index: usize,
    /// Number of read bytes of current file (required for series of split files)
    f_in_read_count: u64,
}

impl ReadInput {
    /// Initializes struct, opens input file, gets input file size, fills split list
    /// 
    /// # Arguments
    /// - `f_in_path`: File input path
    /// - `chunk_size`: Chunk size in bytes
    /// - `f_in_header_size`: Header size of file to be decrypted, required for calculating remaining file size
    /// 
    /// # Returns
    /// - `Ok(Self)` on success
    /// - `Err(...)` when an I/O or conversion error occurs
    pub fn new(f_in_path: &PathBuf, chunk_size: usize, f_in_header_size: u64) -> Result<Self> {
        let f_in = File::open(f_in_path)?;

        let mut f_in_total_size = 0;
        let mut f_in_split = vec![];
        // for decryption (f_in_header_size != 0) and splitted files:
        // get sum of file sizes and fill split list with file sizes
        if f_in_header_size != 0 && f_in_path.extension() == Some(std::ffi::OsStr::new(SPLIT_ENC_FILE_EXT)) {
            let mut split_idx = 0;
            while let Ok(meta) = f_in_path.with_extension(format!("c{:02}", split_idx)).metadata() {
                let file_size = meta.len();
                f_in_total_size += file_size;
                f_in_split.push(file_size);
                split_idx += 1;
            }
        } else {
            f_in_total_size = f_in.metadata()?.len();
        }
        
        if f_in_header_size != 0 
        && f_in_total_size < f_in_header_size + (CHA_NONCE_SIZE + CHA_TAG_SIZE + AES_NONCE_SIZE + AES_TAG_SIZE) as u64 {
            return Err("File cannot be decoded".into());
        }

        // header was already read, therefore remaining file size must be reduced by the header's size
        let f_in_total_size_remaining = f_in_total_size - f_in_header_size;

        Ok( Self { f_in, f_in_path: f_in_path.clone(), f_in_total_size_remaining, chunk_size, f_in_split, split_index: 0, f_in_read_count: 0 } )
    }

    /// Calculate how much need to be read for the current chunk, whether it is the final chunk
    /// and how much data is left in the input file.
    /// 
    /// The remaining bytes of the total file (for splits: sum of all splits) to be read is updated in this method.
    /// 
    /// # Returns
    /// - `Ok((read_size, final_chunk))` chunk size to be read and if it is the final chunk
    /// - `Err` if file I/O or variable conversion fails 
    fn input_sizes(&mut self) -> Result<(usize, bool)> {
        let (read_size, final_chunk) = 
            if self.f_in_total_size_remaining <= u64::try_from(self.chunk_size)? {
                // final chunk
                (usize::try_from(self.f_in_total_size_remaining)?, true)
            } else {
                (self.chunk_size, false)
            };

        self.f_in_total_size_remaining -= u64::try_from(read_size)?;

        Ok((read_size, final_chunk))
    }

    /// Read bytes into provided buffer from the configured input file(s).
    ///
    /// If `self.f_in_split` is empty, performs a single read on the current file.
    /// If splits are configured, reads across split files (`.c00`, `.c01`, ...).
    ///
    /// # Arguments
    /// - `buf`: destination buffer to fill with bytes read.
    /// 
    /// # Returns
    /// - `Ok(())` on success
    /// - `Err(...)` on I/O or conversion errors
    pub fn read_files(&mut self, buf: &mut [u8]) -> Result<()> {
        if self.f_in_split.is_empty() {
            self.f_in.read_exact(&mut buf[..])?;
        } else {
            // split input file 
            let mut file_size = self.f_in_split[self.split_index] - self.f_in_read_count;
            let buf_len = u64::try_from(buf.len())?;
            let mut buf_end: u64 = 0;

            while buf_end < buf_len {
                if self.f_in_read_count == self.f_in_split[self.split_index] {
                    self.split_index += 1;
                    let next_f_in_path = self.f_in_path.with_extension(format!("c{:02}", self.split_index));
                    self.f_in = File::open(&next_f_in_path)?;
                    file_size = self.f_in_split[self.split_index];
                    self.f_in_read_count = 0;
                }

                let buf_start = buf_end;
                if (buf_len - buf_start) <= file_size {
                    buf_end = buf_len;
                } else { 
                    buf_end = buf_start + file_size;
                }

                let (s, e) = (usize::try_from(buf_start)?, usize::try_from(buf_end)?);
                self.f_in.read_exact(&mut buf[s..e])?;

                self.f_in_read_count += buf_end - buf_start;
            }
        } 

        Ok(())
    }
}

impl ReadChunk for ReadInput {
    /// Read a single chunk from the logical file(s) and indicate whether it is the final chunk.
    ///
    /// # Returns 
    /// - `Ok((buf_in, final_chunk))` contains the read chunk buffer and if it is the final chunk
    /// - `Err(...)` when an I/O or conversion error occurs
    fn read_chunk(&mut self) -> Result<(Vec<u8>, bool)> {
        let (read_size, final_chunk) = self.input_sizes()?;
        let mut buf_in = vec![0u8; read_size];
        self.read_files(&mut buf_in)?;

        Ok((buf_in, final_chunk))
    }

    fn join_threads(&mut self) -> Result<()> {
        // do nothing
        Ok(())
    }
}


/// Struct for file output
pub struct WriteOutput {
    /// Output file to write processed data to
    f_out: File,
    /// Path of output file
    f_out_path: PathBuf,
    /// List of split sizes for output
    f_out_split: Vec<u64>,
    /// Index into split list
    split_index: usize,
    /// Number of written bytes of current file (required for split operation)
    f_out_write_count: u64,
}

impl WriteOutput {
    /// Initializes struct and creates output file
    ///     
    /// # Arguments
    /// - `f_out_path`: File output path
    /// - `f_out_split`: Vector of split sizes for output files
    ///
    /// # Returns
    /// - `Ok(Self)` on success
    /// - `Err(...)` when an I/O error occurs
    pub fn new(f_out_path: PathBuf, f_out_split: Vec<u64>) -> Result<Self> {
        let f_out = File::create(&f_out_path)?;
        Ok( Self { f_out, f_out_path, f_out_split, split_index: 0, f_out_write_count: 0 } )
    }
}

impl WriteFiles for WriteOutput {
    /// Writes the provided buffer across one or more output files according to the configured splits.
    ///
    /// - If `self.f_out_split` is empty: append the entire buffer to the current output file.
    /// - If `self.f_out_split` contains sizes: fill each target size in order, then create the next file by
    ///   updating `self.f_out_path` extension to `c01`, `c02`, ...
    ///
    /// # Returns
    /// - `Ok(())` on success
    /// - `Err(...)` when an I/O or conversion error occurs
    fn write_files(&mut self, buf: &[u8]) -> Result<()> {
        if self.f_out_split.is_empty() {
            self.f_out.write_all(buf)?;
        } else {
            let mut buf_start: u64 = 0;
            let mut buf_end: u64   = 0;
            let buf_len = u64::try_from(buf.len())?;

            while buf_end < buf_len { 
                if self.f_out_write_count == self.f_out_split[self.split_index] {
                    // next split
                    self.split_index += 1;
                    buf_start = buf_end;

                    // create new file
                    let f_out_name = &mut self.f_out_path;
                    f_out_name.set_extension(format!("c{:02}", self.split_index));
                    self.f_out = File::create(f_out_name)?;
                    self.f_out_write_count = 0;    
                }
                
                if let Some(split_size) = self.f_out_split.get(self.split_index).copied() {
                    buf_end = buf_len.min( buf_start.saturating_add(split_size).saturating_sub(self.f_out_write_count) );
                } else {
                    // there aren't any more elements in the split list: append all coming bytes to the last (current) file,
                    // hence clear the split list, so this while loop won't be run again
                    buf_end = buf_len;
                    self.f_out_split.clear();
                }

                let (s, e) = (usize::try_from(buf_start)?, usize::try_from(buf_end)?);
                self.f_out.write_all( &buf[s..e] )?;
                
                self.f_out_write_count += buf_end - buf_start;
            }
        }
  
        Ok(())
    }
}


/// Struct for common cryptographic I/O operations
pub struct CryptIo;

impl CryptIo {
    /// Performs cryptographic I/O operations and optional compression on a file using chunked processing with multithreading.
    ///
    /// Reads input file in chunks, applies optional compression and two sequential cryptographic functions to each chunk
    /// using parallelism by threads and writes the results.
    ///
    /// # Arguments
    /// - `key_cha`: Cryptographic key for XChaCha20-Poly1305
    /// - `key_aes`: Cryptographic key for AES-256-GCM-SIV 
    /// - `compress`: Compress data before encryption, decompress after decryption
    /// - `crypt_fn`: Cryptographic function processing compression, XChaCha20-Poly1305, AES-256-GCM-SIV
    ///
    /// # Returns
    /// - `Ok(())` on successful completion
    /// - `Err` if file I/O fails, channels fail or cryptographic functions fail   
    #[allow(clippy::type_complexity)]
    pub fn io_chunks(
        key_cha: &SecretSlice<u8>, 
        key_aes: &SecretSlice<u8>,
        compress: bool,
        crypt_fn: fn(
            &SecretSlice<u8>, 
            &SecretSlice<u8>,
            bool,
            Receiver<(Vec<u8>, u32, bool)>, 
            Sender<(Vec<u8>, u32)>,
            usize) -> Vec<thread::JoinHandle<std::result::Result<(), String>>>,
        mut read_input: Box<dyn ReadChunk>,
        mut write_output: Box<dyn WriteFiles + Send>,
    ) -> Result<()> {

        let cpu_count = num_cpus::get();
        let mut chunk_count: u32 = 0; 
        let mut final_chunk = false;
        let (tx_in, rx_in) = bounded(cpu_count * 2);
        let (tx_out, rx_out) = bounded(cpu_count);

        // compress (optionally) and encrypt/decrypt in threads
        let crypt_handles = crypt_fn(key_cha, key_aes, compress, rx_in, tx_out, cpu_count);

        // write output file(s) in a thread
        // chunks have to be ordered first, as durations of parallel threads varies
        let writer_handle = thread::spawn( move || -> std::result::Result<(), String> {  
            let mut pending_chunks = HashMap::new();
            let mut write_index = 0;
            for (buf, index) in rx_out {
                pending_chunks.insert(index, buf);
                while let Some(buf_out) = pending_chunks.remove(&write_index) {
                    write_output.write_files(&buf_out).map_err(|e| e.to_string())?;
                    write_index += 1;
                }
            }
            Ok(())
        });

        // read input file(s)
        while !final_chunk {    
            let buf_in;
            (buf_in, final_chunk) = read_input.read_chunk()?;
            // don't throw error on send, otherwise errors in encryption/decryption aren't shown to user
            if tx_in.send((buf_in, chunk_count, final_chunk)).is_err() { break }
            chunk_count += 1;
        }

        drop(tx_in);

        // get errors of threads spawned in ArchiveRead::new()
        read_input.join_threads()?; 

        // join and error handling of file writer thread
        match writer_handle.join() {
            Ok(Ok(())) => {},
            Ok(Err(e)) => return Err(e.into()),
            Err(panic) => return Err(format!("Writer thread panicked: {:?}", panic).into()),
        }

        // join and error handling of encryption/decryption threads
        for ch in crypt_handles {
            match ch.join() {
                Ok(Ok(())) => {},
                Ok(Err(e)) => return Err(e.into()),
                Err(panic) => return Err(format!("Crypt thread panicked: {:?}", panic).into()),
            }
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
    use std::fs;
    use crate::HEADER_SIZE;

    #[test]
    fn test_input_sizes() {
        let test_file = &PathBuf::from("test_input_sizes.bin");
        
        let data = vec![0u8; 100];
        fs::write(test_file, &data).unwrap();
        
        // Case 1: chunk not final
        // File size 100, header 10 -> remaining 90. Chunk 50.
        let mut ri = ReadInput::new(test_file, 50, 10).unwrap();
        let (read_size, final_chunk) = ri.input_sizes().unwrap();
        assert_eq!(read_size, 50);
        assert!(!final_chunk);
        assert_eq!(ri.f_in_total_size_remaining, 40);

        // Case 2: chunk final
        // Continuing from above: remaining 40. Chunk 50.
        let (read_size, final_chunk) = ri.input_sizes().unwrap();
        assert_eq!(read_size, 40);
        assert!(final_chunk);
        assert_eq!(ri.f_in_total_size_remaining, 0);

        // cleanup
        let _ = fs::remove_file(test_file);
    }

    #[test]
    fn test_read_files() {
        let data0: [u8; 1000] = rand::random();
        fs::write("test_split_in.c00", data0).unwrap();
        let data1: [u8; 4] = rand::random();
        fs::write("test_split_in.c01", data1).unwrap();
        let data2: [u8; 2024] = rand::random();
        fs::write("test_split_in.c02", data2).unwrap();

        // only first split
        let mut buf = [0u8; 1000];
        let f_in_path = &PathBuf::from("test_split_in.c00");
        let mut ri = ReadInput::new(f_in_path, 0, HEADER_SIZE as u64).unwrap();
        ri.read_files(&mut buf).unwrap();
        assert_eq!(buf, data0);

        // all splits
        let mut buf = [0u8; 3028];
        let mut ri = ReadInput::new(f_in_path, 0, HEADER_SIZE as u64).unwrap();
        ri.read_files(&mut buf).unwrap();
        assert_eq!(buf[..], [&data0[..], &data1[..], &data2[..]].concat());

        // 2 reads
        let mut buf0 = [0u8; 4];
        let mut buf1 = [0u8; 2000];
        let mut ri = ReadInput::new(f_in_path, 0, HEADER_SIZE as u64).unwrap();
        ri.read_files(&mut buf0).unwrap();
        assert_eq!(buf0[..], data0[..4]);
        ri.read_files(&mut buf1).unwrap();
        assert_eq!(buf1[..], [&data0[4..], &data1[..], &data2[..1000]].concat());

        // cleanup
        let _ = fs::remove_file("test_split_in.c00");
        let _ = fs::remove_file("test_split_in.c01");
        let _ = fs::remove_file("test_split_in.c02");
    }

    #[test]
    fn test_write_files() {
        let f_out_path = PathBuf::from("test_split_out.c00");
        let buf: [u8; 1024] = rand::random();
        
        // no split
        let split = vec![];
        let mut wo = WriteOutput::new(f_out_path.clone(), split).unwrap();
        wo.write_files(&buf).unwrap();
        assert_eq!(fs::metadata("test_split_out.c00").unwrap().len(), 1024);
        let _ = fs::remove_file("test_split_out.c00");

        // 2 split files, 1 input buffer
        let split = vec![512];
        let mut wo = WriteOutput::new(f_out_path.clone(), split).unwrap();
        wo.write_files(&buf).unwrap();
        assert_eq!(fs::metadata("test_split_out.c00").unwrap().len(), 512);
        assert_eq!(fs::metadata("test_split_out.c01").unwrap().len(), 512);              
        let _ = fs::remove_file("test_split_out.c00");
        let _ = fs::remove_file("test_split_out.c01");

        // 3 split files, 2 input buffers
        let split = vec![1024, 10];
        let mut wo = WriteOutput::new(f_out_path.clone(), split).unwrap();
        wo.write_files(&buf).unwrap();
        wo.write_files(&buf).unwrap();
        assert_eq!(fs::metadata("test_split_out.c00").unwrap().len(), 1024);
        assert_eq!(fs::metadata("test_split_out.c01").unwrap().len(), 10);  
        assert_eq!(fs::metadata("test_split_out.c02").unwrap().len(), 1014);          
        let _ = fs::remove_file("test_split_out.c00");
        let _ = fs::remove_file("test_split_out.c01");
        let _ = fs::remove_file("test_split_out.c02");

        // splits same size as input buffer
        let split = vec![1024, 1024];
        let mut wo = WriteOutput::new(f_out_path.clone(), split).unwrap();
        wo.write_files(&buf).unwrap();
        wo.write_files(&buf).unwrap();
        assert_eq!(fs::metadata("test_split_out.c00").unwrap().len(), 1024);
        assert_eq!(fs::metadata("test_split_out.c01").unwrap().len(), 1024);  
        assert!(fs::metadata("test_split_out.c02").is_err());          
        let _ = fs::remove_file("test_split_out.c00");
        let _ = fs::remove_file("test_split_out.c01");

        // split sizes overflow buffer size
        let split = vec![1, 1024, 12];
        let mut wo = WriteOutput::new(f_out_path.clone(), split).unwrap();
        wo.write_files(&buf).unwrap();
        assert_eq!(fs::metadata("test_split_out.c00").unwrap().len(), 1);
        assert_eq!(fs::metadata("test_split_out.c01").unwrap().len(), 1023);  
        assert!(fs::metadata("test_split_out.c03").is_err()); 
        
        // concat output files and check against input data
        let mut f0 = File::open("test_split_out.c00").unwrap();
        let mut f1 = File::open("test_split_out.c01").unwrap();
        let mut dat0 = vec![];
        f0.read_to_end(&mut dat0).unwrap();
        let mut dat1 = vec![];
        f1.read_to_end(&mut dat1).unwrap();
        dat0.append(&mut dat1);
        assert_eq!(dat0, buf);

        let _ = fs::remove_file("test_split_out.c00");
        let _ = fs::remove_file("test_split_out.c01");
    }

    #[test]
    fn test_read_chunk() {
        let test_file = &PathBuf::from("test_read_chunk.bin");

        let data = vec![1u8; 100];
        fs::write(test_file, &data).unwrap();

        // 10 bytes header, 40 bytes chunk size.
        // Total 100 bytes. Header 10 -> 90 bytes data.
        // Chunk 1: 40 bytes, final=false.
        // Chunk 2: 40 bytes, final=false.
        // Chunk 3: 10 bytes, final=true.
        let mut ri = ReadInput::new(test_file, 40, 10).unwrap();

        // Skip header 
        let mut header = [0u8; 10];
        ri.read_files(&mut header).unwrap();

        let (buf, final_chunk) = ri.read_chunk().unwrap();
        assert_eq!(buf.len(), 40);
        assert_eq!(buf, vec![1u8; 40]);
        assert!(!final_chunk);

        let (buf, final_chunk) = ri.read_chunk().unwrap();
        assert_eq!(buf.len(), 40);
        assert_eq!(buf, vec![1u8; 40]);
        assert!(!final_chunk);

        let (buf, final_chunk) = ri.read_chunk().unwrap();
        assert_eq!(buf.len(), 10);
        assert_eq!(buf, vec![1u8; 10]);
        assert!(final_chunk);

        // cleanup
        let _ = fs::remove_file(test_file);
    }

}