use std::fs::File;
use std::io::{Read, Seek, Write};
use std::path::PathBuf;
use std::thread;
use secrecy::SecretSlice;

use crate::*;

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
}

impl ReadInput {
    /// Initializes struct, opens input file, gets input file size, fills split list
    /// 
    /// # Arguments
    /// - `f_in_path`: File input path
    /// - `chunk_size`: chunk size, if 0, read chunk size from chunk header
    /// - `f_in_header_size`: Header size of file input, required for calculating remaining file size
    /// 
    /// # Returns
    /// - `Ok(Self)` on success
    /// - `Err(...)` when an I/O or conversion error occurs
    pub fn new(f_in_path: PathBuf, chunk_size: usize, f_in_header_size: usize) -> Result<Self> {
        let f_in = File::open(&f_in_path)?;

        let mut f_in_size = 0;
        let mut f_in_split = vec![];
        // for decryption (f_in_header_size != 0) and splitted files:
        // get sum of file sizes and fill split list with file sizes
        if f_in_header_size != 0 && f_in_path.extension() == Some(std::ffi::OsStr::new(SPLIT_ENC_FILE_EXT)) {
            let mut split_idx = 0;
            let mut f_path = f_in_path.clone();
            
            while let Ok(meta) = f_path.metadata() {
                let file_size = meta.len();
                f_in_size += file_size;
                f_in_split.push(file_size);
                split_idx += 1;
                f_path.set_extension(format!("c{:02}", split_idx));
            }
        } else {
            f_in_size = f_in.metadata()?.len();
        }
        
        // header was already read, therefore remaining file size must be reduced by the header's size
        let f_in_size_remaining = f_in_size - u64::try_from(f_in_header_size)?;

        Ok( Self { f_in, f_in_path, f_in_total_size_remaining: f_in_size_remaining, chunk_size, f_in_split, split_index: 0 } )
    }

    /// Calculate how much data is left in the input file, how much need to be read for the current chunk 
    /// and whether it is the final chunk. 
    /// 
    /// The remaining bytes to be read is updated in this method (`self.f_in_size_remaining`).
    /// If compression is used, the chunk size varies. The size is coded in the 3 bytes 
    /// at the start of a chunk in little endian order.
    /// 
    /// # Returns
    /// - `Ok((read_size, final_chunk))` chunk size to be read and if it is the final chunk
    /// - `Err` if file I/O or variable conversion fails 
    fn input_sizes(&mut self) -> Result<(usize, bool)> {
        let cuk_size = if self.chunk_size == 0 {
            // dynamic chunk size
            let mut buf = [0u8; AES_LENGTH_SIZE];
            self.read_files(&mut buf)?;
            self.f_in_total_size_remaining -= u64::try_from(buf.len())?;
            let c_size: [u8; 4] = [&buf[..], &[0]].concat().try_into().unwrap();
            u32::from_le_bytes(c_size)
        } else {
            // static chunk size
            u32::try_from(self.chunk_size)?
        };

        let (read_size, final_chunk) = 
            if self.f_in_total_size_remaining <= u64::from(cuk_size) {
                // final chunk
                (u32::try_from(self.f_in_total_size_remaining)?, true)
            } else {
                (cuk_size, false)
            };

        self.f_in_total_size_remaining -= u64::from(read_size);

        Ok((read_size as usize, final_chunk))
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
            let mut file_remaining = self.f_in_split[self.split_index] - self.f_in.stream_position()?; 
            let buf_len = u64::try_from(buf.len())?;
            let mut buf_start: u64 = 0;
            let mut buf_end: u64   = 0;

            while buf_end < buf_len {
                if buf_end - buf_start == file_remaining {
                    self.split_index += 1;
                    let f_in_name = &mut self.f_in_path;
                    f_in_name.set_extension(format!("c{:02}", self.split_index));
                    if let Ok(f_in) = File::open(&f_in_name) {
                        self.f_in = f_in;
                        file_remaining = self.f_in_split[self.split_index];
                    } else {
                        // no more files
                        break;
                    }
                }

                buf_start = buf_end;
                if (buf_len - buf_start) <= file_remaining {
                    buf_end = buf_len;
                } else { 
                    buf_end = buf_start + file_remaining;
                }

                let (s, e) = (usize::try_from(buf_start)?, usize::try_from(buf_end)?);
                self.f_in.read_exact(&mut buf[s..e])?;
            }
        } 

        Ok(())
    }

    /// Read a single chunk from the logical file(s) and indicate whether it is the final chunk.
    ///
    /// # Returns 
    /// - `Ok((buf_in, final_chunk))` contains the read chunk buffer and if it is the final chunk
    /// - `Err(...)` when an I/O or conversion error occurs
    pub fn read_chunk(&mut self) -> Result<(Vec<u8>, bool)> {
        let (read_size, final_chunk) = self.input_sizes()?;
        let mut buf_in = vec![0u8; read_size];
        self.read_files(&mut buf_in)?;

        Ok((buf_in, final_chunk))
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
    /// Count written bytes during split operation
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

    /// Writes the provided buffer across one or more output files according to the configured splits.
    ///
    /// - If `self.f_out_split` is empty: append the entire buffer to the current output file.
    /// - If `self.f_out_split` contains sizes: fill each target size in order, then create the next file by
    ///   updating `self.f_out_path` extension to `c01`, `c02`, ...
    ///
    /// # Returns
    /// - `Ok(())` on success
    /// - `Err(...)` when an I/O or conversion error occurs
    pub fn write_files(&mut self, buf: &[u8]) -> Result<()> {
        if self.f_out_split.is_empty() {
            self.f_out.write_all(buf)?;
        } else {
            let mut buf_start: u64 = 0;
            let mut buf_end: u64   = 0;
            let buf_len = u64::try_from(buf.len())?;

            while buf_end < buf_len { 
                if self.f_out_split[self.split_index] == self.f_out_write_count {
                    // next split
                    self.split_index += 1;
                    buf_start = buf_end;

                    // create new file
                    let f_out_name = &mut self.f_out_path;
                    f_out_name.set_extension(format!("c{:02}", self.split_index));
                    self.f_out = File::create(f_out_name)?;
                    self.f_out_write_count = 0;    
                }
                
                // if there aren't any more elements in the split list, then append all coming bytes to the last (current) file,
                // hence clear the split list, so this while loop won't be run again
                if let Some(split_chunk) = self.f_out_split.get(self.split_index).copied() {
                    buf_end = buf_len.min( buf_start + (split_chunk - self.f_out_write_count) );
                } else {
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
pub struct CryptIo {
    /// Read chunks from file(s)
    read_input: ReadInput,
    /// Write chunks to file(s)
    write_output: WriteOutput,
}

impl CryptIo {
    /// Initializes struct
    pub fn new(read_input: ReadInput, write_output: WriteOutput) -> Self {
        Self { read_input, write_output }
    }

    /// Performs cryptographic I/O operations on a file using chunked processing with multithreading.
    ///
    /// Reads input file in chunks, applies two sequential cryptographic functions to each chunk
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
    /// - `Err` if file I/O fails or cryptographic functions fail
    #[allow(clippy::type_complexity)]
    pub fn io_chunks(
        &mut self,
        key_cha: &SecretSlice<u8>, 
        key_aes: &SecretSlice<u8>,
        compress: bool,
        crypt_fn: fn(&SecretSlice<u8>, &SecretSlice<u8>, &[u8], u32, bool, bool) -> Result<Vec<u8>>
    ) -> Result<()> {
        let cpu_count = num_cpus::get();
        let mut chunk_count: u32 = 0; 
        let mut final_chunk = false;

        while !final_chunk {
            let mut child_threads = Vec::with_capacity(cpu_count);

            for _ in 0..cpu_count {
                let key_cha = key_cha.clone();
                let key_aes = key_aes.clone();

                let buf_in;
                (buf_in, final_chunk) = self.read_input.read_chunk()?;

                child_threads.push(thread::spawn(move || {
                        let buf_out = crypt_fn(&key_cha, &key_aes, &buf_in, chunk_count, final_chunk, compress)
                            .map_err(|e| e.to_string())?;
                        Ok::<Vec<u8>, String>(buf_out)
                    }));
                
                if final_chunk {
                    break;
                } 
                chunk_count += 1;
            }

            for child in child_threads {
                let buf_out = child.join().unwrap()?;
                self.write_output.write_files(&buf_out)?;
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

    #[test]
    fn test_input_sizes() {
        let test_file = "test_input_sizes.bin";
        
        // --- Static chunk size ---
        let data = vec![0u8; 100];
        fs::write(test_file, &data).unwrap();
        
        // Case 1: Static chunk, not final
        // File size 100, header 10 -> remaining 90. Chunk 50.
        let mut ri = ReadInput::new(PathBuf::from(test_file), 50, 10).unwrap();
        let (read_size, final_chunk) = ri.input_sizes().unwrap();
        assert_eq!(read_size, 50);
        assert!(!final_chunk);
        assert_eq!(ri.f_in_total_size_remaining, 40);

        // Case 2: Static chunk, final
        // Continuing from above: remaining 40. Chunk 50.
        let (read_size, final_chunk) = ri.input_sizes().unwrap();
        assert_eq!(read_size, 40);
        assert!(final_chunk);
        assert_eq!(ri.f_in_total_size_remaining, 0);
        
        // --- Dynamic chunk size ---
        // Case 3: Dynamic chunk, not final
        // File content: [0x10, 0x00, 0x00, ... 100 bytes total]
        // Header size 0 -> remaining 100.
        let mut data = vec![0u8; 100];
        data[0] = 0x10; // cuk_size = 16
        fs::write(test_file, &data).unwrap();

        let mut ri = ReadInput::new(PathBuf::from(test_file), 0, 0).unwrap();
        let (read_size, final_chunk) = ri.input_sizes().unwrap();
        // Reads 3 bytes (header). remaining: 100 - 3 = 97.
        // cuk_size is 16. 97 > 16, so not final.
        // read_size = 16. remaining: 97 - 16 = 81.
        assert_eq!(read_size, 16);
        assert!(!final_chunk);
        assert_eq!(ri.f_in_total_size_remaining, 81);

        // Case 4: Dynamic chunk, final
        // File content: [0x50, 0x00, 0x00, ... 10 bytes total]
        // Header size 0 -> remaining 10.
        let mut data = vec![0u8; 10];
        data[0] = 0x50; // cuk_size = 80
        fs::write(test_file, &data).unwrap();

        let mut ri = ReadInput::new(PathBuf::from(test_file), 0, 0).unwrap();
        let (read_size, final_chunk) = ri.input_sizes().unwrap();
        // Reads 3 bytes. remaining: 10 - 3 = 7.
        // cuk_size is 80. 7 <= 80, so final.
        // read_size = 7. remaining: 7 - 7 = 0.
        assert_eq!(read_size, 7);
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
        let f_in_path = PathBuf::from("test_split_in.c00");
        let mut ri = ReadInput::new(f_in_path.clone(), 0, HEADER_SIZE).unwrap();
        ri.read_files(&mut buf).unwrap();
        assert_eq!(buf, data0);

        // all splits
        let mut buf = [0u8; 3028];
        let mut ri = ReadInput::new(f_in_path.clone(), 0, HEADER_SIZE).unwrap();
        ri.read_files(&mut buf).unwrap();
        assert_eq!(buf[..], [&data0[..], &data1[..], &data2[..]].concat());

        // 2 reads
        let mut buf0 = [0u8; 4];
        let mut buf1 = [0u8; 2000];
        let mut ri = ReadInput::new(f_in_path.clone(), 0, HEADER_SIZE).unwrap();
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
        let test_file = "test_read_chunk.bin";

        // --- Static chunk size ---
        let data = vec![1u8; 100];
        fs::write(test_file, &data).unwrap();

        // 10 bytes header, 40 bytes chunk size.
        // Total 100 bytes. Header 10 -> 90 bytes data.
        // Chunk 1: 40 bytes, final=false.
        // Chunk 2: 40 bytes, final=false.
        // Chunk 3: 10 bytes, final=true.
        let mut ri = ReadInput::new(PathBuf::from(test_file), 40, 10).unwrap();

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

        // --- Dynamic chunk size ---
        // Each chunk starts with 3 bytes (LE) length.
        // Chunk 1: 5 bytes data. Header: [0x05, 0x00, 0x00]. Total 8 bytes.
        // Chunk 2: 2 bytes data. Header: [0x02, 0x00, 0x00]. Total 5 bytes.
        let mut dynamic_data = vec![0x05, 0x00, 0x00];
        dynamic_data.extend_from_slice(&[2u8; 5]);
        dynamic_data.extend_from_slice(&[0x02, 0x00, 0x00]);
        dynamic_data.extend_from_slice(&[3u8; 2]);
        fs::write(test_file, &dynamic_data).unwrap();

        let mut ri = ReadInput::new(PathBuf::from(test_file), 0, 0).unwrap();

        let (buf, final_chunk) = ri.read_chunk().unwrap();
        assert_eq!(buf.len(), 5);
        assert_eq!(buf, vec![2u8; 5]);
        assert!(!final_chunk);

        let (buf, final_chunk) = ri.read_chunk().unwrap();
        assert_eq!(buf.len(), 2);
        assert_eq!(buf, vec![3u8; 2]);
        assert!(final_chunk);

        // cleanup
        let _ = fs::remove_file(test_file);
    }

}