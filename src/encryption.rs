use std::io::Read;
use std::path::{Path, PathBuf};
use std::{fs, thread};
use std::env;
use argon2::Argon2;
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::{Rng, SeedableRng};
use rand::rngs::SysRng;
use rand_chacha::ChaCha20Rng;
use aes_gcm_siv::{aead::{KeyInit, Generate}, Aes256GcmSiv, AeadInOut, Nonce};
use secrecy::{ExposeSecret, ExposeSecretMut, SecretSlice};
use bzip2::Compression;
use bzip2::read::BzEncoder;
use crossbeam_channel::{bounded, Sender, Receiver};
use std::collections::HashMap;

use crate::{Result, SALT_SIZE, KEY_SIZE, CHA_NONCE_SIZE, CHA_TAG_SIZE, AES_NONCE_SIZE, AES_TAG_SIZE, CHUNK_SIZE, 
            COMPRESS_LENGTH_SIZE, ENCRYPTED_FILE_EXT, SPLIT_ENC_FILE_EXT, HEADER_SIZE, FILE_FORMAT_VERSION};
use crate::common::{get_pass_bytes, key_derivation};
use crate::common_io::{CryptIo, ReadInput, WriteOutput, ReadChunk, WriteFiles};
use crate::archive::ArchiveRead;

/// Handles file encryption operations using dual-layer encryption and compression.
///
/// Combines ChaCha20-Poly1305 and AES-256-GCM-SIV for encryption.
pub struct Encryption;

impl Encryption {
    /// Generate a cryptographically secure random salt.
    ///
    /// Produces a fresh salt of length `SALT_SIZE` using a ChaCha20 RNG seeded
    /// from the system RNG. Intended for use with password hashing and key
    /// derivation routines.
    ///
    /// # Returns
    ///
    /// - `Ok([u8; SALT_SIZE])` newly generated salt on success.
    /// - `Err` if RNG initialization fails.
    fn create_salt() -> Result<[u8; SALT_SIZE]> {
        let mut salt = [0u8; SALT_SIZE];
        let mut rng = ChaCha20Rng::try_from_rng(&mut SysRng)?;
        rng.fill_bytes(&mut salt);

        Ok(salt)
    }

    /// Hashes a user-provided password and an optional user-provided key file using Argon2.
    ///
    /// Generates a random salt and derives a cryptographic key from the password and, if available, 
    /// the key file using the Argon2id password hashing algorithm.
    ///
    /// # Arguments
    /// - `keyfilepath`: Optional path to an additional key file
    /// 
    /// # Returns
    /// - `Ok((salt_pw, key))` containing the salt and derived key
    /// - `Err` if password hashing or getting password/key file fails
    fn hash_password(keyfilepath: Option<&PathBuf>) -> Result<([u8; SALT_SIZE], SecretSlice<u8>)> {
        let pass = get_pass_bytes(keyfilepath, true)?;

        let salt_pw = Self::create_salt()?;
        let mut key = SecretSlice::from(vec![0u8; KEY_SIZE]);
        Argon2::default().hash_password_into(pass.expose_secret(), &salt_pw, key.expose_secret_mut())
            .map_err(|e| format!("Failed to hash password: {:?}", e))?;

        Ok((salt_pw, key))
    }

    /// Derive independent ChaCha20 and AES keys and their salts from a master key.
    ///
    /// Generates two independent random salts and expands the provided `key` with
    /// HKDF-SHA256 to produce two 32-byte keys.
    ///
    /// # Arguments
    /// - `key`: master secret material to expand (kept in `SecretSlice<u8>`).
    ///
    /// # Returns
    /// - `Ok(( [u8; SALT_SIZE], SecretSlice<u8>, [u8; SALT_SIZE], SecretSlice<u8> ))` on success.
    /// - `Err` if HKDF expansion or random salt generation fails.
    #[allow(clippy::type_complexity)]
    fn derive_keys(key: &SecretSlice<u8>) -> Result<([u8; SALT_SIZE], SecretSlice<u8>, [u8; SALT_SIZE], SecretSlice<u8>)> {
        let salt_cha = Self::create_salt()?;
        let salt_aes = Self::create_salt()?;

        let key_cha = key_derivation(key, &salt_cha, "xchacha20poly1305".as_bytes())?;
        let key_aes = key_derivation(key, &salt_aes, "-aes-256-gcm-siv-".as_bytes())?;

        Ok((salt_cha, key_cha, salt_aes, key_aes))
    }
   
    /// Encrypt a single chunk with XChaCha20-Poly1305 and per-chunk sequencing info.
    ///
    /// This generates a fresh random nonce and then computes a modified nonce used 
    /// for encryption by XOR'ing:
    /// - `nonce[0]` with `final_chunk`, and
    /// - the subsequent bytes with the little-endian bytes of `chunk_count`
    ///
    /// The encryption uses the modified nonce, but the original nonce
    /// (`nonce_org`) is appended to the resulting output so the stream can be
    /// reconstructed and the modified nonce recomputed during decryption.
    /// The nonce is appended (and not prepended) for faster execution.
    /// 
    /// The stored `nonce_org` plus the caller-supplied `chunk_count` and
    /// `final_chunk` are required to reconstruct the exact nonce during decryption. 
    /// Mismatched values will cause decryption failures.
    /// 
    /// This construction aims to provide sequence/truncation
    /// protection by deriving a per-chunk nonce from the random base nonce plus
    /// explicit chunk metadata.
    /// 
    /// # Arguments
    /// - `cipher`: XChaCha20-Poly1305 cipher struct initialized with key.
    /// - `buf_inout`: data-in: plaintext bytes to encrypt (one chunk); data-out: containing ciphertext (+ authentication tag) + nonce
    /// - `chunk_count`: zero-based chunk index (incremented per chunk). Must be
    ///   the same value used when decrypting this chunk.
    /// - `final_chunk`: `true` if this is the last chunk of the file,
    ///   `false` otherwise. Also must match the value used at decryption.
    ///
    /// # Returns
    /// - `Ok()` on successful encryption
    /// - `Err(...)` if encryption fails
    pub fn cha_encrypt_buffer(cipher: &XChaCha20Poly1305, buf_inout: &mut Vec<u8>, chunk_count: u32, final_chunk: bool) -> Result<()> {
        let mut nonce =  XNonce::try_generate()?;
        let nonce_org = nonce;

        // change nonce by XOR of chunk count and final chunk flag
        // that prevents reordering or truncation of chunk sequence
        nonce[0] ^= u8::from(final_chunk);
        for (i, ccb) in chunk_count.to_le_bytes().iter().enumerate() {
            nonce[i+1] ^= ccb;
        }
        cipher.encrypt_in_place(&nonce, &[], buf_inout)?;
        buf_inout.extend(nonce_org);
        Ok(())
    }

    /// Encrypts a buffer using AES-256-GCM-SIV.
    ///
    /// Generates a random nonce and encrypts the buffer. The output includes
    /// the ciphertext and the nonce for transmission.
    /// The nonce is appended (and not prepended) for faster execution.
    /// 
    /// # Arguments
    /// - `cipher`: AES-256-GCM-SIV cipher struct initialized with key.
    /// - `buf_inout`: data-in: plaintext bytes to encrypt (one chunk); data-out: containing ciphertext (+ authentication tag) + nonce
    ///
    /// # Returns
    /// - `Ok()` on successful encryption
    /// - `Err(...)` if encryption fails
    pub fn aes_encrypt_buffer(cipher: &Aes256GcmSiv, buf_inout: &mut Vec<u8>) -> Result<()> {
        let nonce = Nonce::try_generate()?;
        cipher.encrypt_in_place(&nonce, &[], buf_inout)?;
        buf_inout.extend(&nonce);
        Ok(())
    }

    /// Compresses a byte buffer using bzip2 compression.
    ///
    /// Uses bzip2 with best compression level to compress the provided input
    /// buffer and returns the resulting bytes. Intended for compressing a
    /// single chunk before encryption.
    ///
    /// # Arguments
    /// - `buf`: input bytes to compress
    ///
    /// # Returns
    /// - `Ok(compressed_bytes)` on success
    /// - `Err` if compression or I/O fails
    pub fn compress_buffer(buf: &[u8]) -> Result<Vec<u8>> {
        let mut compressor = BzEncoder::new(buf, Compression::best());
        let mut compressed_data = Vec::with_capacity(CHUNK_SIZE + CHUNK_SIZE / 10);
        compressor.read_to_end(&mut compressed_data)?;

        Ok(compressed_data)
    }

    /// Re-segments compressed fragments into fixed-size output chunks.
    /// 
    /// Reads compressed pieces from `rx_c` (each item is `(compressed_bytes, orig_idx, final_flag)`),
    /// reorders them by `orig_idx` and appends each compressed fragment prefixed by its
    /// length (using `COMPRESS_LENGTH_SIZE` bytes) into an internal output buffer. When the
    /// internal buffer reaches or exceeds `CHUNK_SIZE` a `CHUNK_SIZE`-sized chunk is emitted
    /// to `tx_e` as `(Vec<u8>, new_chunk_count, new_final_chunk)`. Any remainder is kept and
    /// combined with subsequent fragments. After the input channel closes, any remaining data
    /// is emitted as a final chunk.
    /// 
    /// # Arguments
    /// - `rx_c`: receiver of compressed fragments `(Vec<u8>, u32, bool)`.
    /// - `tx_e`: sender for re-segmented chunks `(Vec<u8>, u32, bool)`.
    /// 
    /// # Returns
    /// - `Ok(())` on successful re-segmentation and sending of all output chunks.
    /// - `Err(...)` if a size conversion, IO, or channel send fails.
    pub fn resegment(rx_c: Receiver<(Vec<u8>, u32, bool)>, tx_e: Sender<(Vec<u8>, u32, bool)>) -> Result<()> {
        let mut pending_chunks = HashMap::new();
        let mut out_index = 0;
        let mut new_chunk_count: u32 = 0;
        let mut new_final_chunk = false;
        let mut buf_out = Vec::with_capacity(CHUNK_SIZE * 2);

        for (buf_zip, chunk_count, final_chunk) in rx_c {
            pending_chunks.insert(chunk_count, (buf_zip, final_chunk));

            while let Some((buf_in, final_chunk)) = pending_chunks.remove(&out_index) {
                // add length of compressed data before compressed data
                let buf_in_len: [u8; 4] = u32::try_from(buf_in.len())?.to_le_bytes();
                buf_out.extend(&buf_in_len[..COMPRESS_LENGTH_SIZE]);
                buf_out.extend(buf_in);
                out_index += 1;

                while buf_out.len() >= CHUNK_SIZE {
                    let new_chunk = buf_out.drain(..CHUNK_SIZE).collect();
                    if final_chunk && buf_out.is_empty() { new_final_chunk = true }
                    
                    tx_e.send((new_chunk, new_chunk_count, new_final_chunk))?;
                    
                    new_chunk_count += 1;
                }
            }
        }
 
        if !buf_out.is_empty() {
            new_final_chunk = true;
            tx_e.send((buf_out, new_chunk_count, new_final_chunk))?;
        }

        Ok(())
    }

    /// Creates the multithreaded encryption pipeline and returns thread handles.
    ///
    /// Spawns worker threads to process incoming plaintext chunks from `rx_in` and
    /// send encrypted chunks to `tx_out`. Behavior depends on `compress`:
    /// - If `compress == true`:
    ///   - Spawns `cpu_count` compression threads. Each compression thread reads
    ///     `(Vec<u8>, u32, bool)` from `rx_in`, compresses the chunk and sends
    ///     `(Vec<u8>, u32, bool)` into an internal compression channel.
    ///   - Spawns one resegmentation thread that reads ordered compressed pieces
    ///     from the compression channel, packs length-prefixed compressed fragments
    ///     into CHUNK_SIZE-sized output buffers (preserving sequence), and forwards
    ///     `(Vec<u8>, u32, bool)` into the encryption channel.
    /// - Regardless of `compress`, spawns `cpu_count` encryption threads. Each
    ///   encryption thread reads `(Vec<u8>, u32, bool)` from the encryption channel
    ///   (or directly from `rx_in` when `compress == false`), applies the per-chunk
    ///   XChaCha20-Poly1305 encryption (including chunk_count/final_chunk sequencing),
    ///   then AES-256-GCM-SIV on the result, and sends `(Vec<u8>, u32)` to `tx_out`.
    ///
    /// # Arguments
    /// - `cipher_cha`: cipher struct for XChaCha20-Poly1305 encryption
    /// - `cipher_aes`: cipher struct for AES-256-GCM-SIV encryption
    /// - `compress`: enable compression + resegment stage when true.
    /// - `rx_in`: receiver for input plaintext chunks `(data, chunk_count, final_flag)`.
    /// - `tx_out`: sender for encrypted output `(encrypted_chunk, chunk_count)`.
    /// - `cpu_count`: number of worker threads to spawn.
    ///
    /// # Returns
    /// - `Vec<thread::JoinHandle<Result<(), String>>>` handles for all spawned threads.
    pub fn encrypt_pipe(
        cipher_cha: &XChaCha20Poly1305, 
        cipher_aes: &Aes256GcmSiv,
        compress: bool, 
        rx_in: Receiver<(Vec<u8>, u32, bool)>, 
        tx_out: Sender<(Vec<u8>, u32)>, 
        cpu_count: usize
    ) -> Vec<thread::JoinHandle<std::result::Result<(), String>>> {

        // number of threads used for encryption and compression
        let c_thread_cnt;
        let e_thread_cnt;
        if compress {
            c_thread_cnt = 1.max(cpu_count * 9 / 10);
            e_thread_cnt = 1.max(cpu_count - c_thread_cnt);
        } else {
            c_thread_cnt = 0;
            e_thread_cnt = cpu_count;
        }
        
        let (tx_e, rx_e) = bounded(cpu_count * 2);

        let mut thread_handles = Vec::with_capacity(cpu_count * 2 + 1);

        if compress {
            let (tx_c, rx_c) = bounded(cpu_count);

            // compression threads
            for _ in 0..c_thread_cnt {
                let rx_in = rx_in.clone();
                let tx_c = tx_c.clone();

                thread_handles.push(thread::spawn( move || -> std::result::Result<(), String> {  
                    for (buf_in, chunk_count, final_chunk) in rx_in {
                        let buf_zip = Self::compress_buffer(&buf_in).map_err(|e| e.to_string())?;
                        if tx_c.send((buf_zip, chunk_count, final_chunk)).is_err() { break }
                    }
                    Ok(())
                }));
            }

            // re-segmentation thread
            {
                let rx_c = rx_c.clone();
                let tx_e = tx_e.clone();
                thread_handles.push(thread::spawn( move || -> std::result::Result<(), String> {  
                    Self::resegment(rx_c, tx_e).map_err(|e| e.to_string())?;
                    Ok(())
                }));
            }
        }

        // encryption threads
        for _ in 0..e_thread_cnt {
            let cipher_cha= cipher_cha.clone();
            let cipher_aes = cipher_aes.clone();
            let rx_in = if compress { rx_e.clone() } else { rx_in.clone() };
            let tx_out = tx_out.clone();

            thread_handles.push(thread::spawn( move || -> std::result::Result<(), String> {  
                for (mut buf_inout, chunk_count, final_chunk) in rx_in {
                    buf_inout.reserve(CHA_NONCE_SIZE + CHA_TAG_SIZE + AES_NONCE_SIZE + AES_TAG_SIZE);
                    Self::cha_encrypt_buffer(&cipher_cha, &mut buf_inout, chunk_count, final_chunk).map_err(|e| e.to_string())?;
                    Self::aes_encrypt_buffer(&cipher_aes, &mut buf_inout).map_err(|e| e.to_string())?;
                    if tx_out.send((buf_inout, chunk_count)).is_err() { break }
                }
                Ok(())
            }));
        }

        thread_handles
    }

    /// Resolves and prepares input and output paths for the encryption process.
    ///
    /// Determines whether the input path represents a directory (which requires
    /// archiving). Constructs the final output file path by applying the correct
    /// extension depending on whether splitting is enabled, and redirects output
    /// to the target directory if specified. If archiving a directory, it returns
    /// the directory that should be stripped during archiving to keep
    /// paths relative.
    ///
    /// # Arguments
    /// - `filepath_in`: Path to the input file or directory to be encrypted.
    /// - `working_dir`: Path to current working directory
    /// - `dirpath_out`: Optional path to a directory where the encrypted output should be saved.
    /// - `no_split`: Boolean flag indicating if output splitting is disabled.
    ///
    /// # Returns
    /// - `Ok((filepath_out, build_archive, strip_dir_in))` containing:
    ///   - `filepath_out`: The resolved absolute path of the output encrypted file.
    ///   - `build_archive`: Boolean indicating whether the input is a directory.
    ///   - `strip_dir_in`: Optional directory path that should be stripped from the start of the absolute archive path.
    /// - `Err` if absolute path resolution fails.
    fn set_paths(filepath_in: &Path, working_dir: &Path, dirpath_out: Option<&PathBuf>, no_split: bool) -> Result<(PathBuf, bool, Option<PathBuf>)> {
        assert!(filepath_in.is_absolute());
    
        let build_archive = filepath_in.is_dir();

        let mut filepath_out = filepath_in.to_path_buf();
        // if input path is the root (e.g. "/"), so without directory name, add a name for the archive
        if build_archive && filepath_in.file_name().is_none() {    
            filepath_out.push("archive");
        }
        if no_split {
            filepath_out.add_extension(ENCRYPTED_FILE_EXT);
        } else {
            filepath_out.add_extension(SPLIT_ENC_FILE_EXT);
        }
       
        // use output directory path or current working directory
        let output_dir =
        if let Some(dir_out) = dirpath_out {
            assert!(dir_out.is_absolute());
            dir_out
        } else {
            working_dir
        };
        let filename_out = filepath_out.file_name().unwrap();
        filepath_out = output_dir.join(filename_out);

        let mut strip_dir_in = None;
        if build_archive {
            if let Some(parent_path) = filepath_in.parent() {
                strip_dir_in = Some(parent_path.to_path_buf());
            } else {
                strip_dir_in = Some(filepath_in.to_path_buf());
            }
        }

        Ok((filepath_out, build_archive, strip_dir_in))
    }

    /// Creates header of output file. 
    /// 
    /// Salts are required unencrypted, the other data is encrypted.
    /// 
    /// # Arguments
    /// - `salt_pw`: salt of password hash
    /// - `salt_cha`: salt of the ChaCha key derivation 
    /// - `salt_aes`: salt of the AES key derivation
    /// - `compress`: compression enabled
    /// - `archive`: archiving enabled
    /// - `cipher_cha`: cipher struct for ChaCha encryption
    /// - `cipher_aes`: cipher struct for AES encryption
    /// 
    /// # Returns
    /// - `Ok(header)` contains header on success
    /// - `Err` if encryption or random data generation fails
    fn create_header(salt_pw: &[u8], salt_cha: &[u8], salt_aes: &[u8], compress: bool, archive: bool, cipher_cha: &XChaCha20Poly1305, cipher_aes: &Aes256GcmSiv) -> Result<Vec<u8>> {
        let mut header = Vec::with_capacity(HEADER_SIZE);

        //
        // cleartext header part
        //
        header.extend(salt_pw);
        header.extend(salt_cha);
        header.extend(salt_aes);

        //
        // encrypted header part
        //
        
        // random filler data
        let mut random_data = [0u8; 2];
        let mut rng = ChaCha20Rng::try_from_rng(&mut SysRng)?;
        rng.fill_bytes(&mut random_data);

        // add some randomness to the constant data
        let mut buf_inout = vec![
            random_data[0],
            FILE_FORMAT_VERSION, 
            random_data[1],
            u8::from(compress) | (u8::from(archive) << 1),
        ];
        buf_inout.reserve(CHA_NONCE_SIZE + CHA_TAG_SIZE + AES_NONCE_SIZE + AES_TAG_SIZE);

        Self::cha_encrypt_buffer(cipher_cha, &mut buf_inout, u32::MAX, false)?;
        Self::aes_encrypt_buffer(cipher_aes, &mut buf_inout)?;

        header.extend(buf_inout);

        Ok(header)
    }

    /// Encrypts a file or a directory using dual-layer encryption (ChaCha20 + AES-256-GCM-SIV) 
    /// with optional compression.
    ///
    /// Prompts user for password, derives master key using Argon2, derives keys for 
    /// ChaCha20 and AES-256-GCM-SIV, compresses (on demand) and encrypts the file/directory in
    /// chunks across multiple threads. Output file gets `.cce` extension. Or output can 
    /// be split into several files, which get extensions `.c00`, `.c01`, `.c02`, ...
    /// 
    /// # Arguments
    /// - `filepath_in`: Path to input file or directory to encrypt
    /// - `dirpath_out`: Optional path to an output directory
    /// - `keyfilepath`: Optional path to an additional key file
    /// - `compress`: Compress input file before encryption
    /// - `split`: List of output split sizes; if empty, no split is done.
    ///
    /// # Returns
    /// - `Ok(())` on successful encryption
    /// - `Err` if file operations, password handling, or encryption fails
    pub fn encrypt(filepath_in: &PathBuf, dirpath_out: Option<&PathBuf>, keyfilepath: Option<&PathBuf>, compress: bool, split: Vec<u64>, verbose: bool) -> Result<()> {

        let (mut filepath_out, build_archive, strip_dir) = Self::set_paths(filepath_in, &env::current_dir()?, dirpath_out, split.is_empty())?;

        // ask for password, before there can be error messages of archive 
        let (salt_pw, key) = Self::hash_password(keyfilepath)?;
        let (salt_cha, key_cha, salt_aes, key_aes) = Self::derive_keys(&key)?;
        let cipher_cha = XChaCha20Poly1305::new_from_slice(key_cha.expose_secret())?;
        let cipher_aes = Aes256GcmSiv::new_from_slice(key_aes.expose_secret())?;

        // output directory path is used
        // create a new directory after password entry: 
        // if password entry failed or user breaks execution at password entry, filesystem stays unchanged
        if let Some(dir_out) = dirpath_out && !dir_out.exists() {
            fs::create_dir_all(dir_out)?;
        }

        // canonicalize directory part, as relative output path elements like ".." might not be resolved
        filepath_out = filepath_out.parent().unwrap().canonicalize()?.join(filepath_out.file_name().unwrap());

        if verbose {
            println!("------------------------");
            println!("File format version: {}", FILE_FORMAT_VERSION);
            println!("Compression:         {}", if compress {"on"} else {"off"} );
            println!("Archiving:           {}", if build_archive {"on"} else {"off"} );
            println!("------------------------");
            println!("Output will be written to file {}", filepath_out.display());
        }

        let read_input: Box<dyn ReadChunk> = if build_archive {
            Box::new( ArchiveRead::new(filepath_in, &filepath_out, &strip_dir.unwrap(), verbose) ) 
        } else {
            Box::new( ReadInput::new(filepath_in, CHUNK_SIZE, 0)? )
        };

        // set write parameters and create output file
        let mut write_output = Box::new( WriteOutput::new(filepath_out, split)? );
     
        // create and write header
        let header = Self::create_header(&salt_pw, &salt_cha, &salt_aes, compress, build_archive, &cipher_cha, &cipher_aes)?;
        write_output.write_files(&header)?;

        CryptIo::io_chunks(&cipher_cha, &cipher_aes, compress, Self::encrypt_pipe, read_input, write_output)?;
        
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
    use std::path;
    use crate::decryption::Decryption;

    #[test]
    fn test_hash_password_encrypt() {
        // salt and key should differ for each call
        let (salt1, key1) = Encryption::hash_password(None).unwrap();
        let (salt2, key2) = Encryption::hash_password(None).unwrap();
        assert_ne!(salt1, salt2);
        assert_ne!(key1.expose_secret(), key2.expose_secret());
        // salt, key should not be all zeros
        assert_ne!(salt1, [0u8; SALT_SIZE]);
        assert_ne!(key1.expose_secret(), [0u8; KEY_SIZE]);

        // key file does not exist
        assert!(Encryption::hash_password(Some(&PathBuf::from("test_miss"))).is_err());
    }

    #[test]
    fn test_derive_keys_encrypt() {
        let key: [u8; 32] = rand::random();
        let key_sec = SecretSlice::from(key.to_vec());

        let (salt_cha, key_cha, salt_aes, key_aes) = Encryption::derive_keys(&key_sec).unwrap();
        // Check sizes
        assert_eq!(salt_cha.len(), SALT_SIZE);
        assert_eq!(salt_aes.len(), SALT_SIZE);
        assert_eq!(key_cha.expose_secret().len(), KEY_SIZE);
        assert_eq!(key_aes.expose_secret().len(), KEY_SIZE);
        
        // ChaCha and AES keys should be different from each other
        assert_ne!(key_cha.expose_secret(), key_aes.expose_secret());
        
        // Salts should not be all zeros
        assert_ne!(salt_cha, [0u8; SALT_SIZE]);
        assert_ne!(salt_aes, [0u8; SALT_SIZE]);
        
        // Keys should not be all zeros
        assert_ne!(key_cha.expose_secret(), [0u8; KEY_SIZE]);
        assert_ne!(key_aes.expose_secret(), [0u8; KEY_SIZE]);
        
        // The two salts should be different from each other
        assert_ne!(salt_cha, salt_aes);

        // Salts and keys should be different on each call
        let (salt_cha2, key_cha2, salt_aes2, key_aes2) = Encryption::derive_keys(&key_sec).unwrap();
        assert_ne!(salt_cha, salt_cha2);
        assert_ne!(salt_aes, salt_aes2);
        assert_ne!(key_cha.expose_secret(), key_cha2.expose_secret());
        assert_ne!(key_aes.expose_secret(), key_aes2.expose_secret());
    }

    #[test]
    fn test_chacha_crypt_buffer() {
        let key: [u8; 32]  = rand::random();
        let key = SecretSlice::from(key.to_vec());
        let cipher_cha = XChaCha20Poly1305::new_from_slice(key.expose_secret()).unwrap();
        let data: [u8; 100] = rand::random();

        let mut encrypt_data = data.to_vec();
        Encryption::cha_encrypt_buffer(&cipher_cha, &mut encrypt_data, 0, false).unwrap();
        assert_eq!(encrypt_data.len(), data.len() + CHA_NONCE_SIZE + CHA_TAG_SIZE);

        let mut decrypt_data = encrypt_data.clone();
        Decryption::cha_decrypt_buffer(&cipher_cha, &mut decrypt_data, 0, false).unwrap();
        assert_eq!(data, decrypt_data[..]);

        // second encryption must produce different output of the same input
        let mut encrypt_data2 = data.to_vec();
        Encryption::cha_encrypt_buffer(&cipher_cha, &mut encrypt_data2, 0, false).unwrap();
        // nonce part (at the end) must be different
        assert_ne!(
            encrypt_data[encrypt_data.len() - CHA_NONCE_SIZE..],
            encrypt_data2[encrypt_data2.len() - CHA_NONCE_SIZE..]
        );
        // encrypted data part must be different
        assert_ne!(
            encrypt_data[..encrypt_data.len() - CHA_NONCE_SIZE],
            encrypt_data2[..encrypt_data2.len() - CHA_NONCE_SIZE]
        );

        // corrupt nonce (at the end of the buffer)
        let mut bad_data = encrypt_data.clone();
        let last_idx = bad_data.len() - 1;
        bad_data[last_idx] ^= 0xFF;
        assert!(Decryption::cha_decrypt_buffer(&cipher_cha, &mut bad_data, 0, false).is_err());

        // corrupt data
        let mut bad_data = encrypt_data.clone();
        bad_data[0] ^= 0xFF;
        assert!(Decryption::cha_decrypt_buffer(&cipher_cha, &mut bad_data, 0, false).is_err());

        // wrong key
        let mut bad_key = key.clone();
        bad_key.expose_secret_mut()[0] ^= 0xFF;
        let bad_cipher_cha = XChaCha20Poly1305::new_from_slice(bad_key.expose_secret()).unwrap();
        let mut bad_data = encrypt_data.clone();
        assert!(Decryption::cha_decrypt_buffer(&bad_cipher_cha, &mut bad_data, 0, false).is_err());

        // wrong final chunk flag
        let mut bad_data = encrypt_data.clone();
        assert!(Decryption::cha_decrypt_buffer(&cipher_cha, &mut bad_data, 0, true).is_err());

        // wrong chunk count
        let mut bad_data = encrypt_data.clone();
        assert!(Decryption::cha_decrypt_buffer(&cipher_cha, &mut bad_data, 1, false).is_err());

        // different values for chunk count and final chunk flag
        let mut encrypt_data = data.to_vec();
        Encryption::cha_encrypt_buffer(&cipher_cha, &mut encrypt_data, 0, true).unwrap();
        let mut decrypt_data = encrypt_data.clone();
        Decryption::cha_decrypt_buffer(&cipher_cha, &mut decrypt_data, 0, true).unwrap();
        assert_eq!(data, decrypt_data[..]);

        let mut encrypt_data = data.to_vec();
        Encryption::cha_encrypt_buffer(&cipher_cha, &mut encrypt_data, 42, false).unwrap();
        let mut decrypt_data = encrypt_data.clone();
        Decryption::cha_decrypt_buffer(&cipher_cha, &mut decrypt_data, 42, false).unwrap();
        assert_eq!(data, decrypt_data[..]);

        let mut encrypt_data = data.to_vec();
        Encryption::cha_encrypt_buffer(&cipher_cha, &mut encrypt_data, 0x1000_0000, true).unwrap();
        let mut decrypt_data = encrypt_data.clone();
        Decryption::cha_decrypt_buffer(&cipher_cha, &mut decrypt_data, 0x1000_0000, true).unwrap();
        assert_eq!(data, decrypt_data[..]);

        let mut encrypt_data = data.to_vec();
        Encryption::cha_encrypt_buffer(&cipher_cha, &mut encrypt_data, 0xFFFF_FFFF, false).unwrap();
        let mut decrypt_data = encrypt_data.clone();
        Decryption::cha_decrypt_buffer(&cipher_cha, &mut decrypt_data, 0xFFFF_FFFF, false).unwrap();
        assert_eq!(data, decrypt_data[..]);

        // empty input data
        let mut encrypt_data = Vec::new();
        Encryption::cha_encrypt_buffer(&cipher_cha, &mut encrypt_data, 0, false).unwrap();
        assert_eq!(encrypt_data.len(), CHA_NONCE_SIZE + CHA_TAG_SIZE);
        let mut decrypt_data = encrypt_data.clone();
        Decryption::cha_decrypt_buffer(&cipher_cha, &mut decrypt_data, 0, false).unwrap();
        assert_eq!(decrypt_data.len(), 0);

        // large input data
        let data_big = vec![0u8; CHUNK_SIZE * 2 + 123];
        let mut encrypt_data = data_big.clone();
        Encryption::cha_encrypt_buffer(&cipher_cha, &mut encrypt_data, 0, false).unwrap();
        let mut decrypt_data = encrypt_data.clone();
        Decryption::cha_decrypt_buffer(&cipher_cha, &mut decrypt_data, 0, false).unwrap();
        assert_eq!(data_big, decrypt_data[..]);
    }

    #[test]
    fn test_aes_crypt_buffer() {
        let key: [u8; 32]  = rand::random();
        let key = SecretSlice::from(key.to_vec());
        let cipher_aes = Aes256GcmSiv::new_from_slice(key.expose_secret()).unwrap();
        let data: [u8; 100] = rand::random();

        let mut encrypt_data = data.to_vec();
        Encryption::aes_encrypt_buffer(&cipher_aes, &mut encrypt_data).unwrap();
        assert_eq!(encrypt_data.len(), data.len() + AES_NONCE_SIZE + AES_TAG_SIZE);

        let mut decrypt_data = encrypt_data.clone();
        Decryption::aes_decrypt_buffer(&cipher_aes, &mut decrypt_data).unwrap();
        assert_eq!(data, decrypt_data[..]);

        // second encryption must produce different output of the same input
        let mut encrypt_data2 = data.to_vec();
        Encryption::aes_encrypt_buffer(&cipher_aes, &mut encrypt_data2).unwrap();
        // nonce part (at the end of the buffer) must be different
        assert_ne!(
            encrypt_data[encrypt_data.len() - AES_NONCE_SIZE..],
            encrypt_data2[encrypt_data2.len() - AES_NONCE_SIZE..]
        );
        // encrypted data part must be different
        assert_ne!(
            encrypt_data[..encrypt_data.len() - AES_NONCE_SIZE],
            encrypt_data2[..encrypt_data2.len() - AES_NONCE_SIZE]
        );

        // corrupt nonce (at the end of the buffer)
        let mut bad_data = encrypt_data.clone();
        let last_idx = bad_data.len() - 1;
        bad_data[last_idx] ^= 0xFF;
        assert!(Decryption::aes_decrypt_buffer(&cipher_aes, &mut bad_data).is_err());

        // corrupt data
        let mut bad_data = encrypt_data.clone();
        bad_data[0] ^= 0xFF;
        assert!(Decryption::aes_decrypt_buffer(&cipher_aes, &mut bad_data).is_err());

        // wrong key
        let mut bad_key = key.clone();
        bad_key.expose_secret_mut()[0] ^= 0xFF;
        let bad_cipher_aes = Aes256GcmSiv::new_from_slice(bad_key.expose_secret()).unwrap();
        let mut bad_data = encrypt_data.clone();
        assert!(Decryption::aes_decrypt_buffer(&bad_cipher_aes, &mut bad_data).is_err());
    }

    #[test]
    fn test_de_compress_buffer() {
        let dat_in = "Hello test".repeat(10);

        // compress
        let out_z = Encryption::compress_buffer(dat_in.as_bytes()).unwrap();
        assert!(out_z.len() < dat_in.len());
        assert!(!out_z.is_empty());

        //decompress
        let dat_out = Decryption::decompress_buffer(&out_z).unwrap();
        assert_eq!(dat_in.as_bytes(), dat_out);

        // empty input
        let out_z = Encryption::compress_buffer(&[]).unwrap();
        assert!(!out_z.is_empty());
        let dat_out = Decryption::decompress_buffer(&out_z).unwrap();
        assert!(dat_out.is_empty());
    }

    #[test]
    fn test_encrypt_resegment() {
        let (tx_c, rx_c) = bounded(3);
        let (tx_e, rx_e) = bounded(3);
        
        let dat0 = vec![0; CHUNK_SIZE];
        let dat1 = vec![1; CHUNK_SIZE];
        tx_c.send((dat0, 0, false)).unwrap();
        tx_c.send((dat1, 1, false)).unwrap();
        thread::spawn( move || {
            Encryption::resegment(rx_c, tx_e).unwrap();
        });
        let (rdat0, rcount0, rfinal0) = rx_e.recv().unwrap();
        let (rdat1, rcount1, rfinal1) = rx_e.recv().unwrap();
        assert_eq!(rdat0[..COMPRESS_LENGTH_SIZE], CHUNK_SIZE.to_le_bytes()[..COMPRESS_LENGTH_SIZE]);
        assert_eq!(rdat0[COMPRESS_LENGTH_SIZE..], vec![0; CHUNK_SIZE - COMPRESS_LENGTH_SIZE]);
        assert_eq!(rdat1[..COMPRESS_LENGTH_SIZE], vec![0; COMPRESS_LENGTH_SIZE]);
        assert_eq!(rdat1[COMPRESS_LENGTH_SIZE..2 * COMPRESS_LENGTH_SIZE], CHUNK_SIZE.to_le_bytes()[..COMPRESS_LENGTH_SIZE]);
        assert_eq!(rdat1[2 * COMPRESS_LENGTH_SIZE..], vec![1; CHUNK_SIZE - 2 * COMPRESS_LENGTH_SIZE]);
        assert_eq!(rcount0, 0);
        assert_eq!(rcount1, 1);
        assert!(!rfinal0);
        assert!(!rfinal1);

        let dat2 = vec![2u8; 1000];
        let dat3 = vec![3u8; CHUNK_SIZE];
        let dat4 = vec![4u8; CHUNK_SIZE];
        tx_c.send((dat4, 4, true)).unwrap();
        tx_c.send((dat2, 2, false)).unwrap();
        tx_c.send((dat3, 3, false)).unwrap();
        drop(tx_c);
        let (rdat2, rcount2, rfinal2) = rx_e.recv().unwrap();
        let (rdat3, rcount3, rfinal3) = rx_e.recv().unwrap();
        let (rdat4, rcount4, rfinal4) = rx_e.recv().unwrap();
        assert_eq!(rdat2.len(), CHUNK_SIZE);
        assert_eq!(rdat3.len(), CHUNK_SIZE);
        assert_eq!(rdat4.len(), 1015);
        assert_eq!(rdat4, vec![4; 1015]);
        assert_eq!(rcount2, 2);
        assert_eq!(rcount3, 3);
        assert_eq!(rcount4, 4);
        assert!(!rfinal2);
        assert!(!rfinal3);
        assert!(rfinal4);
    }

     #[test]
    fn test_decrypt_resegment() {
        let (tx_e, rx_e) = bounded(3);
        let (tx_c, rx_c) = bounded(4);

        let mut dat0 = Vec::new();
        dat0.extend(&1000u32.to_le_bytes()[..COMPRESS_LENGTH_SIZE]);
        dat0.extend( vec![0; 1000]);
        dat0.extend(&2000u32.to_le_bytes()[..COMPRESS_LENGTH_SIZE]);
        dat0.extend( vec![1; 2000]);
        dat0.extend(&(CHUNK_SIZE - 3000).to_le_bytes()[..COMPRESS_LENGTH_SIZE]);
        dat0.extend( vec![2; CHUNK_SIZE - 3000]);

        let mut dat1 = Vec::new();
        dat1.extend(&CHUNK_SIZE.to_le_bytes()[..COMPRESS_LENGTH_SIZE]);
        dat1.extend( vec![3; CHUNK_SIZE]);

        tx_e.send((dat0, 0)).unwrap();
        tx_e.send((dat1, 1)).unwrap();
        thread::spawn( move || {
            Decryption::resegment(rx_e, tx_c).unwrap();
        });
        let (rdat0, rcount0) = rx_c.recv().unwrap();
        let (rdat1, rcount1) = rx_c.recv().unwrap();
        let (rdat2, rcount2) = rx_c.recv().unwrap();
        let (rdat3, rcount3) = rx_c.recv().unwrap();
        assert_eq!(rdat0, vec![0; 1000]);
        assert_eq!(rdat1, vec![1; 2000]);
        assert_eq!(rdat2, vec![2; CHUNK_SIZE - 3000]);
        assert_eq!(rdat3, vec![3; CHUNK_SIZE]);
        assert_eq!(rcount0, 0);
        assert_eq!(rcount1, 1);
        assert_eq!(rcount2, 2);
        assert_eq!(rcount3, 3);
    }

    #[test]
    fn test_crypt_general() {
        // create file with random data for encryption
        let filepath_in = path::absolute(PathBuf::from("test_cc.bin")).unwrap();
        let mut filepath_out = filepath_in.clone();
        filepath_out.add_extension(ENCRYPTED_FILE_EXT);

        // create random input file
        let mut data = vec![0; 1024 * 3000];
        rand::rng().fill_bytes(&mut data);
        fs::write(&filepath_in, &data).unwrap();

        // encrypt, decrypt
        Encryption::encrypt(&filepath_in, None, None, false, vec![], false).unwrap();
        assert!(filepath_out.exists());
        // encrypted file must be different than original data
        assert_ne!(data, fs::read(&filepath_out).unwrap());
        Decryption::decrypt(&filepath_out, None, None, false, false).unwrap();

        // read and compare decrypted file against backup
        let decrypt_data = fs::read(&filepath_in).unwrap();
        assert_eq!(data, decrypt_data[..]);

        // decrypt with keyfile should fail
        let filepath_kf = PathBuf::from("test_another_key.bin");
        fs::write(&filepath_kf, vec![0; 1024]).unwrap();
        assert!(Decryption::decrypt(&filepath_out, None, Some(&filepath_kf), false, false).is_err());

        // with compression
        fs::write(&filepath_in, &data).unwrap();
        Encryption::encrypt(&filepath_in, None, None, true, vec![], false).unwrap();
        Decryption::decrypt(&filepath_out, None, None, false, false).unwrap();
        let decrypt_data = fs::read(&filepath_in).unwrap();
        assert_eq!(data, decrypt_data[..]);

        // encrypt with output directory
        let out_enc_dir = path::absolute(PathBuf::from("test_cc_enc_dir")).unwrap();
        Encryption::encrypt(&filepath_in, Some(&out_enc_dir), None, false, vec![], false).unwrap();
        assert!(&out_enc_dir.join(&filepath_out).exists());
        // decrypt with output directory
        let out_dec_dir = path::absolute(PathBuf::from("test_cc_dec_dir")).unwrap();
        Decryption::decrypt(&out_enc_dir.join(&filepath_out), Some(&out_dec_dir), None, false, false).unwrap();
        assert!(&out_dec_dir.join(&filepath_in).exists());
        let decrypt_data = fs::read(out_dec_dir.join(&filepath_in)).unwrap();
        assert_eq!(data, decrypt_data[..]);
        // decrypt with output directory and list-archive mode - shouldn't have any effect
        Decryption::decrypt(&out_enc_dir.join(&filepath_out), Some(&out_dec_dir), None, false, true).unwrap();
        assert!(&out_dec_dir.join(&filepath_in).exists());

        // cleanup
        let _ = fs::remove_file(&filepath_in);
        let _ = fs::remove_file(&filepath_out);
        let _ = fs::remove_file(&filepath_kf);
        let _ = fs::remove_dir_all(&out_enc_dir);
        let _ = fs::remove_dir_all(&out_dec_dir);
    }

    #[test]
    fn test_crypt_with_keyfile() {
        // create file with random data for encryption
        let filepath_in = path::absolute(PathBuf::from("test_cc_kf.bin")).unwrap();
        let mut filepath_out = filepath_in.clone();
        filepath_out.add_extension(ENCRYPTED_FILE_EXT);
        let filepath_kf = PathBuf::from("test_key.bin");
        
        let mut data = vec![0; 1024 * 1024];
        rand::rng().fill_bytes(&mut data);
        fs::write(&filepath_in, &data).unwrap();

        let mut data_kf = vec![0; 1024 * 1024 * 2];
        rand::rng().fill_bytes(&mut data_kf);
        fs::write(&filepath_kf, &data_kf).unwrap();

        // use keyfile, encrypt, decrypt
        Encryption::encrypt(&filepath_in, None, Some(&filepath_kf), false, vec![], false).unwrap();
        Decryption::decrypt(&filepath_out, None, Some(&filepath_kf), false, false).unwrap();

        // read and compare decrypted file against original data
        let decrypt_data = fs::read(&filepath_in).unwrap();
        assert_eq!(data, decrypt_data[..]);

        // decrypt without key file
        assert!(Decryption::decrypt(&filepath_out, None, None, false, false).is_err());

        // key file does not exist
        assert!(Encryption::encrypt(&filepath_in, None, Some(&PathBuf::from("test_miss")), false, vec![], false).is_err());
        assert!(Decryption::decrypt(&filepath_out, None, Some(&PathBuf::from("test_miss")), false, false).is_err());

        // input file does not exist
        assert!(Encryption::encrypt(&path::absolute(PathBuf::from("test_miss")).unwrap(), None, None, false, vec![], false).is_err());
        assert!(Decryption::decrypt(&PathBuf::from("test_miss.cce"), None, None, false, false).is_err());
        assert!(!fs::exists("test_miss").unwrap());
        assert!(!fs::exists("test_miss.cce").unwrap());

        // with compression
        fs::write(&filepath_in, &data).unwrap();
        Encryption::encrypt(&filepath_in, None, Some(&filepath_kf), true, vec![], false).unwrap();
        Decryption::decrypt(&filepath_out, None, Some(&filepath_kf), false, false).unwrap();
        let decrypt_data = fs::read(&filepath_in).unwrap();
        assert_eq!(data, decrypt_data[..]);

        // cleanup
        let _ = fs::remove_file(&filepath_in);
        let _ = fs::remove_file(&filepath_out);
        let _ = fs::remove_file(&filepath_kf);
    }

    #[test]
    fn test_crypt_split() {
        let filepath_in = path::absolute(PathBuf::from("test_cc_split.bin")).unwrap();
        let mut filepath_out = filepath_in.clone();
        filepath_out.add_extension(ENCRYPTED_FILE_EXT);

        // create random input file
        let mut data = vec![0; 1024 * 3000];
        rand::rng().fill_bytes(&mut data);
        fs::write(&filepath_in, &data).unwrap();

        // encrypt and split output
        Encryption::encrypt(&filepath_in, None, None, false, vec![1048576, 12], false).unwrap();

        // concatenate spilt output files
        let mut data_concat = fs::read("test_cc_split.bin.c00").unwrap();
        data_concat.extend(fs::read("test_cc_split.bin.c01").unwrap());
        data_concat.extend(fs::read("test_cc_split.bin.c02").unwrap());
        fs::write(&filepath_out, &data_concat).unwrap();

        Decryption::decrypt(&filepath_out, None, None, false, false).unwrap();
        // read and compare decrypted file against original data
        let decrypt_data = fs::read(&filepath_in).unwrap();
        assert_eq!(data, decrypt_data[..]);

        // concatenate files with decrypt
        let _ = fs::remove_file(&filepath_in);
        let _ = fs::remove_file(&filepath_out);
        Decryption::decrypt(&PathBuf::from("test_cc_split.bin.c00"), None, None, false, false).unwrap();
        // read and compare decrypted file against original data
        let decrypt_data = fs::read(&filepath_in).unwrap();
        assert_eq!(data, decrypt_data[..]);

        // with compression
        Encryption::encrypt(&filepath_in, None, None, true, vec![11, 12, 1024*100], false).unwrap();
        Decryption::decrypt(&PathBuf::from("test_cc_split.bin.c00"), None, None, false, false).unwrap();
        let decrypt_data = fs::read(&filepath_in).unwrap();
        assert_eq!(data, decrypt_data[..]);

        // cleanup
        let _ = fs::remove_file(&filepath_in);
        let _ = fs::remove_file(&filepath_out);
        let _ = fs::remove_file("test_cc_split.bin.c00");
        let _ = fs::remove_file("test_cc_split.bin.c01");
        let _ = fs::remove_file("test_cc_split.bin.c02");
        let _ = fs::remove_file("test_cc_split.bin.c03");
    }

    #[test]
    fn test_crypt_archive() {
        // Create directory with files that should be archived
        let dir_path = PathBuf::from("test_cc_archive");
        let _ = fs::remove_dir_all(&dir_path);
        fs::create_dir_all(&dir_path).unwrap();
        
        let file1 = dir_path.join("file1.bin");
        let mut data1 = vec![0; CHUNK_SIZE * 10 + 12345];
        rand::rng().fill_bytes(&mut data1);
        fs::write(&file1, &data1).unwrap();

        let file2 = dir_path.join("file2.bin");
        let mut data2 = vec![0; CHUNK_SIZE];
        rand::rng().fill_bytes(&mut data2);
        fs::write(&file2, &data2).unwrap();

        // sub-directory for links
        let sub_dir = dir_path.join("links");
        fs::create_dir(&sub_dir).unwrap();

        // create symlink
        let symlink1 = sub_dir.join("symlink1.bin");
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(PathBuf::from("..").join("file1.bin"), &symlink1).unwrap();
        }
        #[cfg(windows)]
        {
            std::os::windows::fs::symlink_file(PathBuf::from("..").join("file1.bin"), &symlink1).unwrap();
        }

        // create hardlink
        let hardlink2 = sub_dir.join("hardlink2.bin");
        fs::hard_link(&file2, &hardlink2).unwrap();

        // Build archive of directory and encrypt it
        Encryption::encrypt(&dir_path.canonicalize().unwrap(), None, None, false, vec![], false).unwrap();

        // Delete the original files before extracting to verify recreation
        fs::remove_dir_all(&dir_path).unwrap();
        assert!(!dir_path.exists());
        
        // Decrypt and rebuild archived directory
        let archive_path = dir_path.with_extension(ENCRYPTED_FILE_EXT);
        Decryption::decrypt(&archive_path, None, None, false, false).unwrap();

        // Verify structure is fully recreated
        assert!(dir_path.exists());
        assert!(file1.exists());
        assert!(file2.exists());
        assert!(&symlink1.exists());
        assert!(&hardlink2.exists());

        // Verify contents
        assert_eq!(fs::read(&file1).unwrap(), data1);
        assert_eq!(fs::read(&file2).unwrap(), data2);
        assert_eq!(fs::read(&symlink1).unwrap(), data1);
        assert_eq!(fs::read(&hardlink2).unwrap(), data2);


        // With output directory and list-archive mode - no output should be created
        let out_dec_dir1 = path::absolute(PathBuf::from("test_cc_dec_dir1")).unwrap();
        let _ = fs::remove_dir_all(&out_dec_dir1);
        Decryption::decrypt(&archive_path, Some(&out_dec_dir1), None, false, true).unwrap();
        assert!(!out_dec_dir1.exists());
        assert!(!out_dec_dir1.join(&file1).exists());

        // With output directory and without list-archive mode - output should be created
        Decryption::decrypt(&archive_path, Some(&out_dec_dir1), None, false, false).unwrap();
        assert!(out_dec_dir1.exists());
        assert!(out_dec_dir1.join(&file1).exists());
        assert_eq!(fs::read(out_dec_dir1.join(&file1)).unwrap(), data1);

        // With output directory, with split, check exclusion of output archive files 
        let out_enc_dir = &dir_path; 
        Encryption::encrypt(&dir_path.canonicalize().unwrap(), Some(&out_enc_dir.canonicalize().unwrap()), None, false, vec![1000,10000], false).unwrap();
        
        let archive_path2 = out_enc_dir.join(&dir_path).with_extension(SPLIT_ENC_FILE_EXT);
        assert!(archive_path2.exists());
        let out_dec_dir2 = path::absolute(PathBuf::from("test_cc_dec_dir2")).unwrap();
        let _ = fs::remove_dir_all(&out_dec_dir2);
        Decryption::decrypt(&archive_path2, Some(&out_dec_dir2), None, false, false).unwrap();
        
        // Verify structure is fully recreated
        assert!(out_dec_dir2.join(&dir_path).exists());
        assert!(out_dec_dir2.join(&file1).exists());
        assert!(out_dec_dir2.join(&file2).exists());
        assert!(out_dec_dir2.join(&symlink1).exists());
        assert!(out_dec_dir2.join(&hardlink2).exists());

        // Verify contents
        assert_eq!(fs::read(out_dec_dir2.join(&file1)).unwrap(), data1);
        assert_eq!(fs::read(out_dec_dir2.join(&file2)).unwrap(), data2);
        assert_eq!(fs::read(out_dec_dir2.join(&symlink1)).unwrap(), data1);
        assert_eq!(fs::read(out_dec_dir2.join(&hardlink2)).unwrap(), data2);

        // Verify exclude of archive files
        assert!(!out_dec_dir2.join(&dir_path).with_added_extension(SPLIT_ENC_FILE_EXT).exists());
        assert!(!out_dec_dir2.join(&dir_path).with_added_extension("c01").exists());
        assert!(!out_dec_dir2.join(&dir_path).with_added_extension("c02").exists());

        let _ = fs::remove_file(&archive_path);
        let _ = fs::remove_file(&archive_path2);
        let _ = fs::remove_dir_all(&dir_path);
        let _ = fs::remove_dir_all(out_enc_dir);
        let _ = fs::remove_dir_all(&out_dec_dir1);
        let _ = fs::remove_dir_all(&out_dec_dir2);
    }

    #[test]
    fn test_set_paths() {
        // Create test files and directories
        let mut test_dir = PathBuf::from("test_set_paths_dir");
        let _ = fs::remove_dir_all(&test_dir);
        fs::create_dir_all(&test_dir).unwrap();
        test_dir = test_dir.canonicalize().unwrap();

        let test_file = test_dir.join("test_file.txt");
        fs::write(&test_file, b"test data").unwrap();

        let sub_dir = test_dir.join("sub_dir");
        fs::create_dir_all(&sub_dir).unwrap();

        let output_dir = test_dir.join("output_dir");
        fs::create_dir_all(&output_dir).unwrap();

        // 1. File input, no output dir, no split
        {
            let (file_out, archive, strip_dir) = Encryption::set_paths(&test_file, &test_dir, None, true).unwrap();
            assert!(!archive);
            assert_eq!(strip_dir, None);
            let mut expected = test_file.clone();
            expected.add_extension(ENCRYPTED_FILE_EXT);
            assert_eq!(file_out, path::absolute(expected).unwrap());
        }

        // 2. File input, no output dir, with split
        {
            let (file_out, archive, strip_dir) = Encryption::set_paths(&test_file, &test_dir, None, false).unwrap();
            assert!(!archive);
            assert_eq!(strip_dir, None);
            let mut expected = test_file.clone();
            expected.add_extension(SPLIT_ENC_FILE_EXT);
            assert_eq!(file_out, path::absolute(expected).unwrap());
        }

        // 3. File input, with output dir, no split
        {
            let (file_out, archive, strip_dir) = Encryption::set_paths(&test_file, &test_dir, Some(&output_dir), true).unwrap();
            assert!(!archive);
            assert_eq!(strip_dir, None);
            let mut expected = test_file.clone();
            expected.add_extension(ENCRYPTED_FILE_EXT);
            let expected_out = path::absolute(output_dir.join(expected.file_name().unwrap())).unwrap();
            assert_eq!(file_out, expected_out);
        }

        // 4. Directory input (sub_dir), no output dir, no split
        {
            let (file_out, archive, strip_dir) = Encryption::set_paths(&sub_dir, &test_dir, None, true).unwrap();
            assert!(archive);
            assert_eq!(strip_dir, Some(test_dir.clone()));
            let mut expected = sub_dir.clone();
            expected.add_extension(ENCRYPTED_FILE_EXT);
            assert_eq!(file_out, path::absolute(expected).unwrap());
        }

        // 5. Directory input (sub_dir), with output dir, with split
        {
            let (file_out, archive, strip_dir) = Encryption::set_paths(&sub_dir, &test_dir, Some(&output_dir), false).unwrap();
            assert!(archive);
            assert_eq!(strip_dir, Some(test_dir.clone()));
            let mut expected = PathBuf::from("sub_dir");
            expected.add_extension(SPLIT_ENC_FILE_EXT);
            let expected_out = path::absolute(output_dir.join(expected.file_name().unwrap())).unwrap();
            assert_eq!(file_out, expected_out);
        }

        // 6. Directory input without parent/file_name (e.g. "/")
        {
            let root_path = 
            if cfg!(unix) {
                PathBuf::from("/")
            } else {
                PathBuf::from("c:/")
            };
            let (file_out, archive, strip_dir) = Encryption::set_paths(&root_path, &test_dir, None, true).unwrap();
            assert!(archive);
            assert_eq!(strip_dir, Some(root_path.clone()));
            let mut expected = test_dir.join("archive");
            expected.add_extension(ENCRYPTED_FILE_EXT);
            assert_eq!(file_out, expected);
        }

        // Clean up
        let _ = fs::remove_dir_all(&test_dir);
    }
}