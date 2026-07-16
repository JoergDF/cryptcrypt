use std::io::Read;
use std::path::{self, PathBuf};
use std::{fs, thread};
use std::env;
use argon2::Argon2;
use chacha20poly1305::{XChaCha20Poly1305};
use rand::{Rng, SeedableRng};
use rand::rngs::SysRng;
use rand_chacha::ChaCha20Rng;
use aes_gcm_siv::{aead::{Aead, KeyInit, OsRng}, Aes256GcmSiv, AeadCore};
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
    /// - `Ok([u8; SALT_SIZE])` — newly generated salt on success.
    /// - `Err` — if RNG initialization fails.
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
    /// - `key` — master secret material to expand (kept in `SecretSlice<u8>`).
    ///
    /// # Returns
    /// - `Ok(( [u8; SALT_SIZE], SecretSlice<u8>, [u8; SALT_SIZE], SecretSlice<u8> ))` on success.
    /// - `Err` — if HKDF expansion or random salt generation fails.
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
    /// (`nonce_org`) is prepended to the resulting output so the stream can be
    /// reconstructed and the modified nonce recomputed during decryption.
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
    /// - `key` — 32-byte ChaCha key held in a `SecretSlice<u8>`.
    /// - `buf` — plaintext bytes to encrypt (one chunk).
    /// - `chunk_count` — zero-based chunk index (incremented per chunk). Must be
    ///   the same value used when decrypting this chunk.
    /// - `final_chunk` — `true` if this is the last chunk of the file,
    ///   `false` otherwise. Also must match the value used at decryption.
    ///
    /// # Returns
    /// - `Ok(encrypted_data)` containing nonce + ciphertext (+ authentication tag)
    /// - `Err(...)` if initialization or encryption fails
    pub fn cha_encrypt_buffer(key: &SecretSlice<u8>, buf: &[u8], chunk_count: u32, final_chunk: bool) -> Result<Vec<u8>> {
        let cipher = XChaCha20Poly1305::new_from_slice(key.expose_secret())
            .map_err(|e| format!("Failed to init encryption: {:?}", e))?;
        let mut nonce = XChaCha20Poly1305::generate_nonce(OsRng);
        let nonce_org = nonce;

        // change nonce by XOR of chunk count and final chunk flag
        // that prevents reordering or truncation of chunk sequence
        nonce[0] ^= u8::from(final_chunk);
        for (i, ccb) in chunk_count.to_le_bytes().iter().enumerate() {
            nonce[i+1] ^= ccb;
        }

        let mut encrypted_buf = cipher.encrypt(&nonce, buf)
            .map_err(|e| format!("Failed to encrypt data: {:?}", e))?;

        let mut combined_data = Vec::with_capacity(CHA_NONCE_SIZE + buf.len() + CHA_TAG_SIZE);
        combined_data.extend(&nonce_org);
        combined_data.append(&mut encrypted_buf);

        Ok(combined_data)
    }

    /// Encrypts a buffer using AES-256-GCM-SIV.
    ///
    /// Generates a random nonce and encrypts the buffer. The output includes
    /// the length of nonce + ciphertext, the nonce and the ciphertext for transmission.
    ///
    /// # Arguments
    /// - `key`: 32‑byte AES key stored in a `SecretSlice<u8>`
    /// - `buf`: Data to encrypt
    ///
    /// # Returns
    /// - `Ok(encrypted_data)` containing nonce + ciphertext (+ authentication tag)
    /// - `Err` if initialization or encryption fails
    pub fn aes_encrypt_buffer(key: &SecretSlice<u8>, buf: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256GcmSiv::new_from_slice(key.expose_secret())
            .map_err(|e| format!("Failed to init encryption: {:?}", e))?;
        let nonce =  Aes256GcmSiv::generate_nonce(OsRng);
        let mut encrypted_buf = cipher.encrypt(&nonce, buf)
            .map_err(|e| format!("Failed to encrypt data: {:?}", e))?;

        let mut combined_data = Vec::with_capacity(AES_NONCE_SIZE + buf.len() + AES_TAG_SIZE);
        combined_data.extend(nonce);
        combined_data.append(&mut encrypted_buf);

        Ok(combined_data)
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
    /// - `key_cha`: ChaCha key for first-layer encryption.
    /// - `key_aes`: AES key for second-layer encryption.
    /// - `compress`: enable compression + resegment stage when true.
    /// - `rx_in`: receiver for input plaintext chunks `(data, chunk_count, final_flag)`.
    /// - `tx_out`: sender for encrypted output `(encrypted_chunk, chunk_count)`.
    /// - `cpu_count`: number of worker threads to spawn.
    ///
    /// # Returns
    /// - `Vec<thread::JoinHandle<Result<(), String>>>` — handles for all spawned threads.
    pub fn encrypt_pipe(
        key_cha: &SecretSlice<u8>, 
        key_aes: &SecretSlice<u8>, 
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
            let key_cha = key_cha.clone();
            let key_aes = key_aes.clone();
            let rx_in = if compress { rx_e.clone() } else { rx_in.clone() };
            let tx_out = tx_out.clone();

            thread_handles.push(thread::spawn( move || -> std::result::Result<(), String> {  
                for (buf_in, chunk_count, final_chunk) in rx_in {
                    let buf_cha = Self::cha_encrypt_buffer(&key_cha, &buf_in, chunk_count, final_chunk).map_err(|e| e.to_string())?;
                    let buf_aes = Self::aes_encrypt_buffer(&key_aes, &buf_cha).map_err(|e| e.to_string())?;
                    if tx_out.send((buf_aes, chunk_count)).is_err() { break }
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
    /// the target working directory that should be set during archiving to keep
    /// paths relative.
    ///
    /// # Arguments
    /// - `filepath_in`: Path to the input file or directory to be encrypted.
    /// - `dirpath_out`: Optional path to a directory where the encrypted output should be saved.
    /// - `no_split`: Boolean flag indicating if output splitting is disabled.
    ///
    /// # Returns
    /// - `Ok((processed_path_in, filepath_out, build_archive, new_working_dir))` containing:
    ///   - `processed_path_in`: The relative input path if archiving, or the original input path.
    ///   - `filepath_out`: The resolved absolute path of the output encrypted file.
    ///   - `build_archive`: Boolean indicating whether the input is a directory.
    ///   - `new_working_dir`: Optional path to the directory that the process should change to before archiving.
    /// - `Err` if absolute path resolution fails.
    fn set_paths(filepath_in: &PathBuf, dirpath_out: Option<&PathBuf>, no_split: bool) -> Result<(PathBuf, PathBuf, bool, Option<PathBuf>)> {
        let build_archive = filepath_in.is_dir();

        let mut filepath_out = filepath_in.clone();
        // if input path is the root or relative (e.g. "/", "."), so without directory name, add a name for the archive
        if build_archive && filepath_in.file_name().is_none() {    
            filepath_out.push("archive");
        }
        if no_split {
            filepath_out.add_extension(ENCRYPTED_FILE_EXT);
        } else {
            filepath_out.add_extension(SPLIT_ENC_FILE_EXT);
        }
        // output directory path is used
        // build path, but create directory after password entry
        if let Some(dir_out) = dirpath_out {
            let filename_out = filepath_out.file_name().unwrap();
            filepath_out = dir_out.join(filename_out);
        }
        filepath_out = path::absolute(filepath_out)?;

        let mut new_working_dir = None;
        let processed_path_in = if build_archive {
            // change directory to parent directory
            if let Some(dir_path) = filepath_in.file_name() {
                if let Some(parent_path) = filepath_in.parent() && parent_path != "" {
                    new_working_dir = Some(parent_path.to_path_buf());
                }
                PathBuf::from(dir_path)
            } else {
                new_working_dir = Some(filepath_in.to_path_buf());
                PathBuf::from(".")
            }
        } else {
            filepath_in.to_path_buf()
        };

        Ok((processed_path_in, filepath_out, build_archive, new_working_dir))
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
    pub fn encrypt(filepath_in: &PathBuf, dirpath_out: Option<&PathBuf>, keyfilepath: Option<&PathBuf>, compress: bool, split: Vec<u64>) -> Result<()> {
        
        let (processed_path_in, filepath_out, build_archive, new_working_dir) = Self::set_paths(filepath_in, dirpath_out, split.is_empty())?;
        if build_archive && let Some(work_dir) = new_working_dir {
            env::set_current_dir(work_dir)?;
        }

        println!("Output will be written to {}", filepath_out.display());

        // ask for password, before there can be error messages of archive 
        let (salt_pw, key) = Self::hash_password(keyfilepath)?;
        let (salt_cha, key_cha, salt_aes, key_aes) = Self::derive_keys(&key)?;

        // output directory path is used
        // create a new directory after password entry: 
        // if password entry failed or user breaks execution on password entry, filesystem stays unchanged
        if let Some(dir_out) = dirpath_out && !dir_out.exists() {
            fs::create_dir_all(dir_out)?;
        }

        let read_input: Box<dyn ReadChunk> = if build_archive {
            Box::new( ArchiveRead::new(&processed_path_in, &filepath_out) ) 
        } else {
            Box::new( ReadInput::new(&processed_path_in, CHUNK_SIZE, 0)? )
        };

        // file header
        //   byte  description
        //      0  version of file format
        //      1  info about file format
        //           bit 0: compression on(1)/off(0)
        //           bit 1: archive
        //  2..33  32-byte-salt of password hash
        // 34..65  32-byte-salt of cha key derivation
        // 66..97  32-byte-salt of aes key derivation
        let mut header = Vec::with_capacity(HEADER_SIZE);
        header.push(FILE_FORMAT_VERSION);
        header.push(u8::from(compress) | (u8::from(build_archive) << 1));
        header.extend(salt_pw);
        header.extend(salt_cha);
        header.extend(salt_aes);

        // set write parameters and create output file
        let mut write_output = Box::new( WriteOutput::new(filepath_out, split)? );

        // write header
        write_output.write_files(&header)?;

        CryptIo::io_chunks(&key_cha, &key_aes, compress, Self::encrypt_pipe, read_input, write_output)?;

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
        let data: [u8; 100] = rand::random();

        let encrypt_data = Encryption::cha_encrypt_buffer(&key, &data, 0, false).unwrap();
        let decrypt_data = Decryption::cha_decrypt_buffer(&key, &encrypt_data, 0, false).unwrap();
        assert_eq!(encrypt_data.len(), data.len() + CHA_NONCE_SIZE + CHA_TAG_SIZE);
        assert_eq!(data, decrypt_data[..]);

        // second encryption must produce different output of the same input
        let encrypt_data2 = Encryption::cha_encrypt_buffer(&key, &data, 0, false).unwrap();
        // nonce part must be different
        assert_ne!(encrypt_data[..CHA_NONCE_SIZE], encrypt_data2[..CHA_NONCE_SIZE]);
        // encrypted data part must be different
        assert_ne!(encrypt_data[CHA_NONCE_SIZE..], encrypt_data2[CHA_NONCE_SIZE..]);

        // corrupt nonce
        let mut bad_data = encrypt_data.clone();
        bad_data[0] ^= 0xFF;
        assert!(Decryption::cha_decrypt_buffer(&key, &bad_data, 0, false).is_err());

        // corrupt data
        let mut bad_data = encrypt_data.clone();
        bad_data[CHA_NONCE_SIZE+1] ^= 0xFF;
        assert!(Decryption::cha_decrypt_buffer(&key, &bad_data, 0, false).is_err());

        // wrong key
        let mut bad_key = key.clone();
        bad_key.expose_secret_mut()[0] ^= 0xFF;
        assert!(Decryption::cha_decrypt_buffer(&bad_key, &encrypt_data, 0, false).is_err());

        // wrong final chunk flag
        assert!(Decryption::cha_decrypt_buffer(&key, &encrypt_data, 0, true).is_err());

        // wrong chunk count
        assert!(Decryption::cha_decrypt_buffer(&key, &encrypt_data, 1, false).is_err());

        // different values for chunk count and final chunk flag
        let encrypt_data = Encryption::cha_encrypt_buffer(&key, &data, 0, true).unwrap();
        let decrypt_data = Decryption::cha_decrypt_buffer(&key, &encrypt_data, 0, true).unwrap();
        assert_eq!(data, decrypt_data[..]);

        let encrypt_data = Encryption::cha_encrypt_buffer(&key, &data, 42, false).unwrap();
        let decrypt_data = Decryption::cha_decrypt_buffer(&key, &encrypt_data, 42, false).unwrap();
        assert_eq!(data, decrypt_data[..]);

        let encrypt_data = Encryption::cha_encrypt_buffer(&key, &data, 0x1000_0000, true).unwrap();
        let decrypt_data = Decryption::cha_decrypt_buffer(&key, &encrypt_data, 0x1000_0000, true).unwrap();
        assert_eq!(data, decrypt_data[..]);

        let encrypt_data = Encryption::cha_encrypt_buffer(&key, &data, 0xFFFF_FFFF, false).unwrap();
        let decrypt_data = Decryption::cha_decrypt_buffer(&key, &encrypt_data, 0xFFFF_FFFF, false).unwrap();
        assert_eq!(data, decrypt_data[..]);

        // empty input data
        let encrypt_data = Encryption::cha_encrypt_buffer(&key, &[], 0, false).unwrap();
        let decrypt_data = Decryption::cha_decrypt_buffer(&key, &encrypt_data, 0, false).unwrap();
        assert_eq!(encrypt_data.len(), CHA_NONCE_SIZE + CHA_TAG_SIZE);
        assert_eq!(decrypt_data.len(), 0);

        // large input data
        let data_big = vec![0u8; CHUNK_SIZE * 2 + 123];
        let encrypt_data = Encryption::cha_encrypt_buffer(&key, &data_big, 0, false).unwrap();
        let decrypt_data = Decryption::cha_decrypt_buffer(&key, &encrypt_data, 0, false).unwrap();
        assert_eq!(data_big, decrypt_data[..]);
    }

    #[test]
    fn test_aes_crypt_buffer() {
        let key: [u8; 32]  = rand::random();
        let key = SecretSlice::from(key.to_vec());
        let data: [u8; 100] = rand::random();

        let encrypt_data = Encryption::aes_encrypt_buffer(&key, &data).unwrap();
        let decrypt_data = Decryption::aes_decrypt_buffer(&key, &encrypt_data).unwrap();
        assert_eq!(encrypt_data.len(), data.len() + AES_NONCE_SIZE + AES_TAG_SIZE);
        assert_eq!(data, decrypt_data[..]);

        // second encryption must produce different output of the same input
        let encrypt_data2 = Encryption::aes_encrypt_buffer(&key, &data).unwrap();
        // nonce part must be different
        assert_ne!(encrypt_data[..AES_NONCE_SIZE], encrypt_data2[..AES_NONCE_SIZE]);
        // encrypted data part must be different
        assert_ne!(encrypt_data[3 + AES_NONCE_SIZE..], encrypt_data2[3 + AES_NONCE_SIZE..]);

        // corrupt 'nonce'
        let mut bad_data = encrypt_data.clone();
        bad_data[1] ^= 0xFF;
        assert!(Decryption::aes_decrypt_buffer(&key, &bad_data).is_err());

        // corrupt 'data'
        let mut bad_data = encrypt_data.clone();
        bad_data[AES_NONCE_SIZE + 1] ^= 0xFF;
        assert!(Decryption::aes_decrypt_buffer(&key, &bad_data).is_err());

        // wrong key
        let mut bad_key = key.clone();
        bad_key.expose_secret_mut()[0] ^= 0xFF;
        assert!(Decryption::aes_decrypt_buffer(&bad_key, &encrypt_data).is_err());
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
    fn test_crypt() {
        // create file with random data for encryption
        let filepath_in = PathBuf::from("test_cc.bin");
        let mut filepath_out = filepath_in.clone();
        filepath_out.add_extension(ENCRYPTED_FILE_EXT);

        // create random input file
        let mut data = vec![0; 1024 * 3000];
        rand::rng().fill_bytes(&mut data);
        fs::write(&filepath_in, &data).unwrap();

        // encrypt, decrypt
        Encryption::encrypt(&filepath_in, None, None, false, vec![]).unwrap();
        assert!(filepath_out.exists());
        // encrypted file must be different than original data
        assert_ne!(data, fs::read(&filepath_out).unwrap());
        Decryption::decrypt(&filepath_out, None, None).unwrap();

        // read and compare decrypted file against backup
        let decrypt_data = fs::read(&filepath_in).unwrap();
        assert_eq!(data, decrypt_data[..]);

        // decrypt with keyfile should fail
        let filepath_kf = PathBuf::from("test_another_key.bin");
        fs::write(&filepath_kf, vec![0; 1024]).unwrap();
        assert!(Decryption::decrypt(&filepath_out, None, Some(&filepath_kf)).is_err());

        // with compression
        fs::write(&filepath_in, &data).unwrap();
        Encryption::encrypt(&filepath_in, None, None, true, vec![]).unwrap();
        Decryption::decrypt(&filepath_out, None, None).unwrap();
        let decrypt_data = fs::read(&filepath_in).unwrap();
        assert_eq!(data, decrypt_data[..]);

        // cleanup
        let _ = fs::remove_file(&filepath_in);
        let _ = fs::remove_file(&filepath_out);
        let _ = fs::remove_file(&filepath_kf);
    }

    #[test]
    fn test_crypt_with_keyfile() {
        // create file with random data for encryption
        let filepath_in = PathBuf::from("test_cc_kf.bin");
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
        Encryption::encrypt(&filepath_in, None, Some(&filepath_kf), false, vec![]).unwrap();
        Decryption::decrypt(&filepath_out, None, Some(&filepath_kf)).unwrap();

        // read and compare decrypted file against original data
        let decrypt_data = fs::read(&filepath_in).unwrap();
        assert_eq!(data, decrypt_data[..]);

        // decrypt without key file
        assert!(Decryption::decrypt(&filepath_out, None, None).is_err());

        // key file does not exist
        assert!(Encryption::encrypt(&filepath_in, None, Some(&PathBuf::from("test_miss")), false, vec![]).is_err());
        assert!(Decryption::decrypt(&filepath_out, None, Some(&PathBuf::from("test_miss"))).is_err());

        // input file does not exist
        assert!(Encryption::encrypt(&PathBuf::from("test_miss"), None, None, false, vec![]).is_err());
        assert!(Decryption::decrypt(&PathBuf::from("test_miss.cce"), None, None).is_err());
        assert!(!fs::exists("test_miss").unwrap());
        assert!(!fs::exists("test_miss.cce").unwrap());

        // with compression
        fs::write(&filepath_in, &data).unwrap();
        Encryption::encrypt(&filepath_in, None, Some(&filepath_kf), true, vec![]).unwrap();
        Decryption::decrypt(&filepath_out, None, Some(&filepath_kf)).unwrap();
        let decrypt_data = fs::read(&filepath_in).unwrap();
        assert_eq!(data, decrypt_data[..]);

        // cleanup
        let _ = fs::remove_file(&filepath_in);
        let _ = fs::remove_file(&filepath_out);
        let _ = fs::remove_file(&filepath_kf);
    }

    #[test]
    fn test_crypt_split() {
        let filepath_in = PathBuf::from("test_cc_split.bin");
        let mut filepath_out = filepath_in.clone();
        filepath_out.add_extension(ENCRYPTED_FILE_EXT);

        // create random input file
        let mut data = vec![0; 1024 * 3000];
        rand::rng().fill_bytes(&mut data);
        fs::write(&filepath_in, &data).unwrap();

        // encrypt and split output
        Encryption::encrypt(&filepath_in, None, None, false, vec![1048576, 12]).unwrap();

        // concatenate spilt output files
        let mut data_concat = fs::read("test_cc_split.bin.c00").unwrap();
        data_concat.extend(fs::read("test_cc_split.bin.c01").unwrap());
        data_concat.extend(fs::read("test_cc_split.bin.c02").unwrap());
        fs::write(&filepath_out, &data_concat).unwrap();

        Decryption::decrypt(&filepath_out, None, None).unwrap();
        // read and compare decrypted file against original data
        let decrypt_data = fs::read(&filepath_in).unwrap();
        assert_eq!(data, decrypt_data[..]);

        // concatenate files with decrypt
        let _ = fs::remove_file(&filepath_in);
        let _ = fs::remove_file(&filepath_out);
        Decryption::decrypt(&PathBuf::from("test_cc_split.bin.c00"), None, None).unwrap();
        // read and compare decrypted file against original data
        let decrypt_data = fs::read(&filepath_in).unwrap();
        assert_eq!(data, decrypt_data[..]);

        // with compression
        Encryption::encrypt(&filepath_in, None, None, true, vec![11, 12, 1024*100]).unwrap();
        Decryption::decrypt(&PathBuf::from("test_cc_split.bin.c00"), None, None).unwrap();
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
        let dir_path = PathBuf::from("test_archive_toplevel");
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

        // Build archive of directory and encrypt it
        Encryption::encrypt(&dir_path, None, None, false, vec![]).unwrap();

        // Delete the original files before extracting to verify recreation
        fs::remove_dir_all(&dir_path).unwrap();
        assert!(!dir_path.exists());
        
        // Decrypt and rebuild archived directory
        let arch_path = dir_path.with_extension(ENCRYPTED_FILE_EXT);
        Decryption::decrypt(&arch_path, None, None).unwrap();

        // Verify structure is fully recreated
        assert!(dir_path.exists());
        assert!(file1.exists());
        assert!(file2.exists());

        // Verify contents
        assert_eq!(fs::read(&file1).unwrap(), data1);
        assert_eq!(fs::read(&file2).unwrap(), data2);

        let _ = fs::remove_dir_all(&dir_path);
        let _ = fs::remove_file(&arch_path);
    }

    #[test]
    fn test_set_paths() {
        // Create temporary test files and directories
        let test_dir = PathBuf::from("test_set_paths_dir");
        let _ = fs::remove_dir_all(&test_dir);
        fs::create_dir_all(&test_dir).unwrap();

        let test_file = test_dir.join("test_file.txt");
        fs::write(&test_file, b"test data").unwrap();

        let sub_dir = test_dir.join("sub_dir");
        fs::create_dir_all(&sub_dir).unwrap();

        let output_dir = test_dir.join("output_dir");
        fs::create_dir_all(&output_dir).unwrap();

        // 1. File input, no output dir, no split
        {
            let (processed_in, file_out, archive, work_dir) = Encryption::set_paths(&test_file, None, true).unwrap();
            assert!(!archive);
            assert_eq!(work_dir, None);
            assert_eq!(processed_in, test_file);
            let mut expected = test_file.clone();
            expected.add_extension(ENCRYPTED_FILE_EXT);
            assert_eq!(file_out, path::absolute(expected).unwrap());
        }

        // 2. File input, no output dir, with split
        {
            let (processed_in, file_out, archive, work_dir) = Encryption::set_paths(&test_file, None, false).unwrap();
            assert!(!archive);
            assert_eq!(work_dir, None);
            assert_eq!(processed_in, test_file);
            let mut expected = test_file.clone();
            expected.add_extension(SPLIT_ENC_FILE_EXT);
            assert_eq!(file_out, path::absolute(expected).unwrap());
        }

        // 3. File input, with output dir, no split
        {
            let (processed_in, file_out, archive, work_dir) = Encryption::set_paths(&test_file, Some(&output_dir), true).unwrap();
            assert!(!archive);
            assert_eq!(work_dir, None);
            assert_eq!(processed_in, test_file);
            let mut expected = test_file.clone();
            expected.add_extension(ENCRYPTED_FILE_EXT);
            let expected_out = path::absolute(output_dir.join(expected.file_name().unwrap())).unwrap();
            assert_eq!(file_out, expected_out);
        }

        // 4. Directory input (sub_dir), no output dir, no split
        {
            let (processed_in, file_out, archive, work_dir) = Encryption::set_paths(&sub_dir, None, true).unwrap();
            assert!(archive);
            assert_eq!(work_dir, Some(test_dir.clone()));
            assert_eq!(processed_in, PathBuf::from("sub_dir"));
            let mut expected = sub_dir.clone();
            expected.add_extension(ENCRYPTED_FILE_EXT);
            assert_eq!(file_out, path::absolute(expected).unwrap());
        }

        // 5. Directory input (sub_dir), with output dir, with split
        {
            let relative_sub_dir = PathBuf::from("test_set_paths_dir/sub_dir");
            let (processed_in, file_out, archive, work_dir) = Encryption::set_paths(&relative_sub_dir, Some(&output_dir), false).unwrap();
            assert!(archive);
            assert_eq!(work_dir, Some(test_dir.clone()));
            assert_eq!(processed_in, PathBuf::from("sub_dir"));
            let mut expected = PathBuf::from("sub_dir");
            expected.add_extension(SPLIT_ENC_FILE_EXT);
            let expected_out = path::absolute(output_dir.join(expected.file_name().unwrap())).unwrap();
            assert_eq!(file_out, expected_out);
        }

        // 6. Directory input without parent/file_name (e.g. ".")
        {
            let dot_path = PathBuf::from(".");
            let (processed_in, file_out, archive, work_dir) = Encryption::set_paths(&dot_path, None, true).unwrap();
            assert!(archive);
            assert_eq!(work_dir, Some(PathBuf::from(".")));
            assert_eq!(processed_in, PathBuf::from("."));
            let mut expected = PathBuf::from("archive");
            expected.add_extension(ENCRYPTED_FILE_EXT);
            assert_eq!(file_out, path::absolute(expected).unwrap());
        }

        // Clean up
        let _ = fs::remove_dir_all(&test_dir);
    }

    #[test]
    #[ignore="only for benchmarking"]
    fn test_crypt_bench() {
        // a file 'ttt' must already exist
        let filepath_in = PathBuf::from("ttt");     
        let mut filepath_out = filepath_in.clone();
        filepath_out.add_extension(ENCRYPTED_FILE_EXT);

        Encryption::encrypt(&filepath_in, None, None, false, vec![]).unwrap();
        Decryption::decrypt(&filepath_out, None, None).unwrap();
    }
}