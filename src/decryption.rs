use std::thread;
use std::io::Read;
use std::path::PathBuf;
use std::collections::HashMap;
use std::fs;
use std::env;
use argon2::Argon2;
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use aes_gcm_siv::{aead::KeyInit, Aes256GcmSiv, AeadInOut, Nonce};
use secrecy::{ExposeSecret, ExposeSecretMut, SecretSlice};
use bzip2::read::BzDecoder;
use crossbeam_channel::{bounded, Sender, Receiver};

use crate::{Result, KEY_SIZE, CHA_NONCE_SIZE, AES_NONCE_SIZE, CHUNK_SIZE, COMPRESS_LENGTH_SIZE, ENCRYPTED_FILE_EXT,
            SPLIT_ENC_FILE_EXT, CHA_TAG_SIZE, AES_TAG_SIZE, HEADER_SIZE, SALT_SIZE, FILE_FORMAT_VERSION};
use crate::common::{get_pass_bytes, key_derivation};
use crate::common_io::{CryptIo, ReadInput, WriteFiles, WriteOutput};
use crate::archive::ArchiveWrite;


/// Handles file decryption operations using dual-layer decryption and decompression.
///
/// Reverses ChaCha20-Poly1305 and AES-256-GCM-SIV encryption applied during encryption.
pub struct Decryption;

impl Decryption {
    /// Hashes a user-provided password using Argon2 with supplied salt and optional key file.
    ///
    /// Derives a cryptographic key from the password using the provided salt, the optional key file,
    /// and Argon2id algorithm, allowing recovery of the original key used for encryption.
    ///
    /// # Arguments
    /// - `salt_pw`: Salt bytes to use for hashing
    /// - `keyfilepath`: Optional path to an additional key file
    ///
    /// # Returns
    /// - `Ok(key)` containing the derived key
    /// - `Err` if password hashing or getting password/key file fails
    fn hash_password(salt_pw: &[u8], keyfilepath: Option<&PathBuf>) -> Result<SecretSlice<u8>> {
        let pass = get_pass_bytes(keyfilepath, false)?;

        let mut key = SecretSlice::from(vec![0u8; KEY_SIZE]);
        Argon2::default().hash_password_into(pass.expose_secret(), salt_pw, key.expose_secret_mut())
            .map_err(|e| format!("Failed to hash password: {:?}", e))?;

        Ok(key)
    }

    /// Derive ChaCha20 and AES keys from a master key and salts.
    ///
    /// Expands the provided master `key` with HKDF-SHA256 using `salt_cha` and
    /// `salt_aes` to produce two independent 32‑byte keys.
    ///
    /// The function returns the derived keys wrapped in `SecretSlice<u8>` so
    /// callers keep key material in secure containers.
    ///
    /// # Arguments
    /// - `salt_cha`: salt for the ChaCha key derivation (expected length: `SALT_SIZE`)
    /// - `salt_aes`: salt for the AES key derivation (expected length: `SALT_SIZE`)
    /// - `key`: master secret material to expand (type: `SecretSlice<u8>`)
    ///
    /// # Returns
    /// - `Ok((key_cha, key_aes))` — tuple of derived keys (`SecretSlice<u8>`) each `KEY_SIZE` bytes long
    /// - `Err` if HKDF expansion or underlying operations fail
    fn derive_keys(salt_cha: &[u8], salt_aes: &[u8], key: &SecretSlice<u8>) -> Result<(SecretSlice<u8>, SecretSlice<u8>)> {
        let key_cha = key_derivation(key, salt_cha, "xchacha20poly1305".as_bytes())?;
        let key_aes = key_derivation(key, salt_aes, "-aes-256-gcm-siv-".as_bytes())?;

        Ok((key_cha, key_aes))
    }

    /// Decrypts a buffer encrypted with XChaCha20-Poly1305 using the per‑chunk nonce modification.
    ///
    /// Extracts the nonce from the end of the buffer and decrypts the remainder.
    /// Verifies authentication tag during decryption.
    /// The function reconstructs the modified nonce by XOR'ing:
    /// - `nonce[0]` with `final_chunk`, and
    /// - `nonce[1..]` with the little‑endian bytes of `chunk_count` (applied starting at index 1).
    /// 
    /// # Arguments
    /// - `cipher`: XChaCha20-Poly1305 cipher struct initialized with key.
    /// - `buf_inout`: data-in: ciphertext (+ authentication tag) + nonce; data-out: decrypted data.
    /// - `chunk_count`: zero‑based chunk index; must match the value used during encryption.
    /// - `final_chunk`: `true` if this is the last chunk; must match the value used during encryption.
    ///
    /// # Returns
    /// - `Ok()` on successful decryption
    /// - `Err` if decryption fails or authentication tag verification fails
    pub fn cha_decrypt_buffer(cipher: &XChaCha20Poly1305, buf_inout: &mut Vec<u8>, chunk_count: u32, final_chunk: bool) -> Result<()> {
        let nonce_pos = buf_inout.len() - CHA_NONCE_SIZE;
        let mut nonce = XNonce::try_from(&buf_inout[nonce_pos..])?;
        
        // change nonce by XOR of final chunk flag and chunk count
        nonce[0] ^= u8::from(final_chunk);
        for (i, ccb) in chunk_count.to_le_bytes().iter().enumerate() {
            nonce[i+1] ^= ccb;
        }
        buf_inout.truncate(nonce_pos);
        cipher.decrypt_in_place(&nonce, &[], buf_inout)
            .map_err(|_e| "Failed to decrypt data!")?; // for better user info
        Ok(())
    }

    /// Decrypts a buffer encrypted with AES-256-GCM-SIV.
    ///
    /// Extracts the nonce from the end of the buffer and decrypts the remainder.
    /// Verifies authentication tag during decryption.
    ///
    /// # Arguments
    /// - `cipher`: Aes256GcmSiv cipher struct initialized with key
    /// - `buf_inout`: data-in: ciphertext (+ authentication tag) + nonce; data-out: decrypted data
    ///
    /// # Returns
    /// - `Ok()` on successful decryption
    /// - `Err` if decryption fails or authentication tag verification fails
    pub fn aes_decrypt_buffer(cipher: &Aes256GcmSiv, buf_inout: &mut Vec<u8>) -> Result<()> {
        let nonce_pos = buf_inout.len() - AES_NONCE_SIZE;
        let nonce = Nonce::try_from(&buf_inout[nonce_pos..])?;
        buf_inout.truncate(nonce_pos);
        cipher.decrypt_in_place(&nonce, &[], buf_inout)
            .map_err(|_e| "Failed to decrypt data!")?; // for better user info
        Ok(())
    }

    /// Decompresses a bzip2-compressed buffer.
    ///
    /// Reads the provided buffer with a bzip2 decoder and returns the
    /// decompressed result. This is the inverse of `Encryption::compress_buffer`.
    ///
    /// # Arguments
    /// - `buf`: compressed input bytes
    ///
    /// # Returns
    /// - `Ok(decompressed_bytes)` on success
    /// - `Err` if decompression or I/O fails
    pub fn decompress_buffer(buf: &[u8]) -> Result<Vec<u8>> {
        let mut decompressor = BzDecoder::new(buf);
        let mut decompressed_data = Vec::with_capacity(CHUNK_SIZE);
        decompressor.read_to_end(&mut decompressed_data)?;

        Ok(decompressed_data)
    }

    /// Re-segments a stream of decrypted fixed-sized fragments into length-prefixed compressed chunks.
    ///
    /// Reads decrypted fragment payloads from `rx_e` (items are `(Vec<u8>, chunk_index)`),
    /// reorders out-of-order fragments using a `HashMap`, concatenates payloads into an
    /// internal buffer and extracts complete compressed entries using the compact length
    /// prefix encoded in the first `COMPRESS_LENGTH_SIZE` bytes. Each extracted compressed
    /// entry is emitted to `tx_c` as `(Vec<u8>, new_chunk_count)`.
    ///
    /// # Arguments
    /// - `rx_e`: receiver of decrypted buffers `(Vec<u8>, chunk_count)` produced by earlier stages.
    /// - `tx_c`: sender for re-segmented compressed chunks `(Vec<u8>, new_chunk_count)`.
    ///
    /// # Returns
    /// - `Ok(())` on successful re-segmentation and sending of all output chunks.
    /// - `Err(...)` if a size conversion, IO, or channel send fails.
    pub fn resegment(rx_e: Receiver<(Vec<u8>, u32)>, tx_c: Sender<(Vec<u8>, u32)>) -> Result<()> {
        let mut pending_chunks = HashMap::new();
        let mut out_index = 0;
        let mut new_chunk_count: u32 = 0;
        let mut buf_out = Vec::with_capacity(CHUNK_SIZE * 2);
        let mut compressed_chunk_len: Option<usize> = None;

        for (buf_e, chunk_count) in rx_e {
            pending_chunks.insert(chunk_count, buf_e);

            while let Some(buf_in) = pending_chunks.remove(&out_index) {
                buf_out.extend(buf_in);
                out_index += 1;

                loop {
                    if let Some(c_chunk_len) = compressed_chunk_len {
                        // length bytes have been read, check if buffer contains enough bytes
                        if buf_out.len() >= c_chunk_len {
                            let new_chunk = buf_out.drain(..c_chunk_len).collect();
                            tx_c.send((new_chunk, new_chunk_count))?;

                            compressed_chunk_len = None;
                            new_chunk_count += 1;
                        } else {
                            break; // not enough data, get more
                        }
                    } else if buf_out.len() >= COMPRESS_LENGTH_SIZE {
                        // get length bytes at the start of a compressed chunk
                        let mut length_bytes: Vec<u8> = buf_out.drain(..COMPRESS_LENGTH_SIZE).collect();
                        length_bytes.push(0);
                        compressed_chunk_len = Some(
                            u32::from_le_bytes(
                                length_bytes.try_into().unwrap()
                            ).try_into()?
                        );
                    } else {
                        break; // not enough data, get more
                    }
                }
            }
        }
        
        if !buf_out.is_empty() {
            return Err("Decryption resegmentation end error".into());
        }

        Ok(())
    }
   
    /// Creates the multithreaded decryption pipeline and returns thread handles.
    ///
    /// Spawns worker threads to reverse the encryption pipeline and produce plaintext chunks
    /// for writing. Behavior depends on `decompress`:
    /// - Always spawns `cpu_count` decryption threads: each reads `(Vec<u8>, chunk_count, final_flag)`
    ///   from `rx_in`, performs AES-256-GCM-SIV decryption, then XChaCha20-Poly1305 decryption
    ///   (reconstructing per-chunk nonce using `chunk_count` and `final_flag`), and sends
    ///   `(Vec<u8>, chunk_count)`.
    /// - If `decompress == true`:
    ///   - Spawns a single re-segmentation thread that reads ordered decrypted inner payloads,
    ///     stitches and parses length-prefixed compressed entries, and forwards `(Vec<u8>, u32)`
    ///     to the decompression channel.
    ///   - Spawns `cpu_count` decompression threads that read `(Vec<u8>, chunk_count)` from the
    ///     re-segmentation output, decompress each entry, and send `(Vec<u8>, chunk_count)` to `tx_out`.
    ///
    /// # Arguments
    /// - `cipher_cha`: cipher struct for XChaCha20-Poly1305 decryption
    /// - `cipher_aes`: cipher struct for AES-256-GCM-SIV decryption
    /// - `decompress`: enable resegment + decompression stages when true.
    /// - `rx_in`: receiver for encrypted input chunks `(data, chunk_count, final_flag)`.
    /// - `tx_out`: sender for final plaintext output `(plaintext_chunk, chunk_count)`.
    /// - `cpu_count`: number of worker threads to spawn.
    ///
    /// # Returns
    /// - `Vec<thread::JoinHandle<std::result::Result<(), String>>>` — handles for all spawned threads.
    pub fn decrypt_pipe(
        cipher_cha: &XChaCha20Poly1305, 
        cipher_aes: &Aes256GcmSiv,
        decompress: bool, 
        rx_in: Receiver<(Vec<u8>, u32, bool)>, 
        tx_out: Sender<(Vec<u8>, u32)>, 
        cpu_count: usize
    ) -> Vec<thread::JoinHandle<std::result::Result<(), String>>> {
        
        // number of threads used for decryption and decompression
        let c_thread_cnt;
        let e_thread_cnt;
        if decompress {
            c_thread_cnt = 1.max(cpu_count * 8 / 10);
            e_thread_cnt = 1.max(cpu_count - c_thread_cnt);
        } else {
            c_thread_cnt = 0;
            e_thread_cnt = cpu_count;
        }

        let (tx_e, rx_e) = bounded(cpu_count * 2);

        let mut thread_handles = Vec::with_capacity(cpu_count * 2 + 1);

        // decryption threads
        for _ in 0..e_thread_cnt {
            let cipher_cha= cipher_cha.clone();
            let cipher_aes = cipher_aes.clone();
            let rx_in = rx_in.clone();
            let tx_e = if decompress { tx_e.clone() } else { tx_out.clone() };

            thread_handles.push(thread::spawn( move || -> std::result::Result<(), String> { 
                for (mut buf_inout, chunk_count, final_chunk) in rx_in {
                    Self::aes_decrypt_buffer(&cipher_aes, &mut buf_inout).map_err(|e| e.to_string())?;
                    Self::cha_decrypt_buffer(&cipher_cha, &mut buf_inout, chunk_count, final_chunk).map_err(|e| e.to_string())?;
                    if tx_e.send((buf_inout, chunk_count)).is_err() { break }
                }
                Ok(())
            }));
        }

        if decompress {
            let (tx_c, rx_c) = bounded(cpu_count * 2);

            // re-segmentation thread
            {
                let rx_e = rx_e.clone();
                let tx_c= tx_c.clone();
                thread_handles.push(thread::spawn( move || -> std::result::Result<(), String> {  
                    Self::resegment(rx_e, tx_c).map_err(|e| e.to_string())?;
                    Ok(())
                }));
            }

            // decompression threads
            for _ in 0..c_thread_cnt {
                let rx_c = rx_c.clone();
                let tx_out = tx_out.clone();

                thread_handles.push(thread::spawn( move || -> std::result::Result<(), String> {
                    for (buf_in, chunk_count) in rx_c {
                        let buf_zip = Self::decompress_buffer(&buf_in).map_err(|e| e.to_string())?;
                        if tx_out.send((buf_zip, chunk_count)).is_err() { break }
                    }
                    Ok(())
                }));
            }
        }        

        thread_handles
    }

    /// Gets unencrypted data of header, i.e. the 3 salt values
    /// 
    /// # Argument:
    /// - `header`: header bytes
    /// 
    /// # Returns:
    /// - `(salt_pw, salt_cha, salt_aes)`: salts for password, chacha key, aes key 
    fn get_unencrypted_header_items(header: &[u8]) -> (&[u8], &[u8], &[u8]) {
        let salt_pw  = &header[..SALT_SIZE];
        let salt_cha = &header[SALT_SIZE..(2 * SALT_SIZE)];
        let salt_aes = &header[(2 * SALT_SIZE)..(3 * SALT_SIZE)];

        (salt_pw, salt_cha, salt_aes)
    }

    /// Gets encrypted data of header
    /// 
    /// # Argument:
    /// - `header`: header bytes
    /// - `cipher_cha`: cipher struct for chacha decryption
    /// - `cipher_aes`: cipher struct for aes decryption
    /// 
    /// # Returns:
    /// - `Ok((file_format_version, compress, archive))` contains on success: version of file format, compression status, whether it's an archive 
    fn get_encrypted_header_items(header: &[u8], cipher_cha: &XChaCha20Poly1305, cipher_aes: &Aes256GcmSiv) -> Result<(u8, bool, bool)> {
        let mut enc_head = Vec::from(&header[(3 * SALT_SIZE)..HEADER_SIZE]);

        Self::aes_decrypt_buffer(cipher_aes, &mut enc_head)?;
        Self::cha_decrypt_buffer(cipher_cha, &mut enc_head, u32::MAX, false)?;

        // evaluate data, ignore random bytes
        let file_format_version = enc_head[1];
        let file_format         = enc_head[3];
        let compress = (file_format & 0x01) != 0;
        let archive  = (file_format & 0x02) != 0;

        Ok((file_format_version, compress, archive))
    }

    /// Decrypts a file encrypted with dual-layer encryption (AES-256-GCM-SIV + ChaCha20).
    ///
    /// Reads and evaluates header from file, prompts user for password, derives master key using Argon2,
    /// derives keys for ChaCha20 and AES-256-GCM-SIV, decrypts the file in chunks across multiple threads. 
    /// Output file has `.cce` suffix removed.
    ///
    /// # Arguments
    /// - `filepath_in`: Path to encrypted input file (must end with `.cce`)
    /// - `dirpath_out`: Option path to an output directory
    /// - `keyfilepath`: Optional path to an additional key file
    ///
    /// # Returns
    /// - `Ok(())` on successful decryption
    /// - `Err` if file operations, password handling, or decryption fails
    pub fn decrypt(filepath_in: &PathBuf, dirpath_out: Option<&PathBuf>, keyfilepath: Option<&PathBuf>, verbose: bool, list_archive: bool) -> Result<()> {
        if filepath_in.is_dir() {
            return Err("Cannot decrypt a directory".into());
        }

        // set read parameters
        let mut read_input = Box:: new( ReadInput::new(
            filepath_in, 
            CHUNK_SIZE + CHA_NONCE_SIZE + CHA_TAG_SIZE + AES_NONCE_SIZE + AES_TAG_SIZE, 
            HEADER_SIZE as u64
        )? );

        // Read file header
        let mut header = [0u8; HEADER_SIZE];
        read_input.read_files(&mut header)?;

        // get salts from header
        let (salt_pw, salt_cha, salt_aes) = Self::get_unencrypted_header_items(&header);

        // get password and keys
        let key = Self::hash_password(salt_pw, keyfilepath)?;
        let (key_cha, key_aes) = Self::derive_keys(salt_cha, salt_aes, &key)?;
        let cipher_cha = XChaCha20Poly1305::new_from_slice(key_cha.expose_secret())?;
        let cipher_aes = Aes256GcmSiv::new_from_slice(key_aes.expose_secret())?;
        
        // get rest of header
        let (file_format_version, compress, archive) = Self::get_encrypted_header_items(&header, &cipher_cha, &cipher_aes)?;

        // check format version
        if file_format_version != FILE_FORMAT_VERSION {
            return Err(format!(
                "This input file format (v{file_format_version}) cannot be decoded with this app version. It requires file format v{FILE_FORMAT_VERSION}."
            ).into());
        }

        let mut filepath_out = PathBuf::from(filepath_in.file_name().unwrap());
        if filepath_in.extension() == Some(std::ffi::OsStr::new(ENCRYPTED_FILE_EXT)) ||
           filepath_in.extension() == Some(std::ffi::OsStr::new(SPLIT_ENC_FILE_EXT)) {
            // remove encrypted-file-extension
            filepath_out.set_extension("");
        } else {
            return Err(format!("Invalid filename, it does not end with .{ENCRYPTED_FILE_EXT} or .{SPLIT_ENC_FILE_EXT}").into())
        }

        // use output directory path ot current working directory
        let output_dir =
        if let Some(dir_out) = dirpath_out {
            // create user-specified output directory, if it is not an archive or archive is not just listed (and directory is missing)
            if ((archive && !list_archive) || !archive) && !dir_out.exists() {
                fs::create_dir_all(dir_out)?;
            }
            // canonicalize directory, as relative output path elements like ".." might not be resolved
            // in list mode, directory might not exist
            if dir_out.exists() {
                dir_out.canonicalize()?
            } else {
                dir_out.to_path_buf()
            }
        } else {
            env::current_dir()?
        };

        filepath_out = output_dir.join(filepath_out);

        if verbose {
            println!("--------------------------");
            println!("File format version: {}", file_format_version);
            println!("Compressed:          {}", compress);
            println!("Archived:            {}", archive);
            println!("--------------------------");
            if archive {
                println!("Archive file will be extracted to directory {}", output_dir.display());
            } else {
                println!("Output will be written to file {}", filepath_out.display());
            }
        }

        // set write parameters and create output file
        let write_output: Box<dyn WriteFiles + Send + 'static> = if archive {
            // convert relative path elements to absolute ones (looks better for verbose print)
            // in list mode, directory might not exist
            let dirpath_out_absolute = dirpath_out.map(|p| 
                if p.exists() { p.canonicalize() } else { Ok(p.to_path_buf()) }
            ).transpose()?;         
            Box::new( ArchiveWrite::new(dirpath_out_absolute, verbose, list_archive) )
        } else {
            Box::new( WriteOutput::new(filepath_out, vec![])? )
        };

        CryptIo::io_chunks(&cipher_cha, &cipher_aes, compress, Self::decrypt_pipe, read_input, write_output)?;

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
    use rand::Rng;
    use crate::SALT_SIZE;

    #[test]
    fn test_hash_password_decrypt() {
        let salt = [1u8; SALT_SIZE];
        // key should be the same for each call
        let key1 = Decryption::hash_password(&salt ,None).unwrap();
        let key2 = Decryption::hash_password(&salt, None).unwrap();
        assert_eq!(key1.expose_secret(), key2.expose_secret());
        // key should not be all zeros
        assert_ne!(key1.expose_secret(), [0u8; KEY_SIZE]);

        // key should change for the same salt, if a keyfile is added
        let filepath_kf = PathBuf::from("test_pw_key.bin");
        let mut data_kf = vec![0; 100];
        rand::rng().fill_bytes(&mut data_kf);
        fs::write(&filepath_kf, &data_kf).unwrap();
        
        let key3 = Decryption::hash_password(&salt, Some(&filepath_kf)).unwrap();
        assert_ne!(key1.expose_secret(), key3.expose_secret());

        // key file does not exist
        assert!(Decryption::hash_password(&salt, Some(&PathBuf::from("test_miss"))).is_err());

        // cleanup
        let _ = fs::remove_file(&filepath_kf);
    }

    #[test]
    fn test_derive_keys_decrypt() {
        let key: [u8; 32] = rand::random();
        let key_sec = SecretSlice::from(key.to_vec());
        let salt_cha: [u8; SALT_SIZE] = rand::random();
        let salt_aes: [u8; SALT_SIZE] = rand::random();

        let (key_cha, key_aes) = Decryption::derive_keys(&salt_cha, &salt_aes, &key_sec).unwrap();

        // Output should have correct sizes
        assert_eq!(key_cha.expose_secret().len(), KEY_SIZE);
        assert_eq!(key_aes.expose_secret().len(), KEY_SIZE);
        
        // Keys should not be all zeros
        assert_ne!(key_cha.expose_secret(), [0u8; KEY_SIZE]);
        assert_ne!(key_aes.expose_secret(), [0u8; KEY_SIZE]);
        
        // ChaCha and AES keys should be different from each other
        assert_ne!(key_cha.expose_secret(), key_aes.expose_secret());

        // Same inputs should produce identical outputs
        let (key_cha2, key_aes2) = Decryption::derive_keys(&salt_cha, &salt_aes, &key_sec).unwrap();
        assert_eq!(key_cha.expose_secret(), key_cha2.expose_secret());
        assert_eq!(key_aes.expose_secret(), key_aes2.expose_secret());

        // Different ChaCha salt
        let mut salt_cha2 = salt_cha;
        salt_cha2[0] ^= 0xFF;
        let (key_cha3, key_aes3) = Decryption::derive_keys(&salt_cha2, &salt_aes, &key_sec).unwrap();
        assert_ne!(key_cha.expose_secret(), key_cha3.expose_secret());
        assert_eq!(key_aes.expose_secret(), key_aes3.expose_secret());

        // Different AES salt
        let mut salt_aes4 = salt_aes;
        salt_aes4[0] ^= 0xFF;
        let (key_cha4, key_aes4) = Decryption::derive_keys(&salt_cha, &salt_aes4, &key_sec).unwrap();
        assert_eq!(key_cha.expose_secret(), key_cha4.expose_secret());
        assert_ne!(key_aes.expose_secret(), key_aes4.expose_secret());

        // Different input key
        let mut key2 = key;
        key2[0] ^= 0xFF;
        let key_sec2 = SecretSlice::from(key2.to_vec());
        let (key_cha5, key_aes5) = Decryption::derive_keys(&salt_cha, &salt_aes, &key_sec2).unwrap();
        assert_ne!(key_cha.expose_secret(), key_cha5.expose_secret());
        assert_ne!(key_aes.expose_secret(), key_aes5.expose_secret());

    }
}