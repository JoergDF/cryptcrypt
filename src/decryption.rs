use std::thread;
use std::io::Read;
use std::path::PathBuf;
use std::collections::HashMap;
use argon2::Argon2;
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use aes_gcm_siv::{aead::{Aead, KeyInit}, Aes256GcmSiv, Nonce};
use secrecy::{ExposeSecret, ExposeSecretMut, SecretSlice};
use bzip2::read::BzDecoder;
use crossbeam_channel::{bounded, Sender, Receiver};

use crate::{Result, KEY_SIZE, CHA_NONCE_SIZE, AES_NONCE_SIZE, CHUNK_SIZE, COMPRESS_LENGTH_SIZE, ENCRYPTED_FILE_EXT,
            SPLIT_ENC_FILE_EXT, CHA_TAG_SIZE, AES_TAG_SIZE, HEADER_SIZE, FILE_FORMAT_VERSION};
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
    /// - `salt_cha` — salt for the ChaCha key derivation (expected length: `SALT_SIZE`)
    /// - `salt_aes` — salt for the AES key derivation (expected length: `SALT_SIZE`)
    /// - `key` — master secret material to expand (type: `SecretSlice<u8>`)
    ///
    /// # Returns
    /// - `Ok((key_cha, key_aes))` — tuple of derived keys (`SecretSlice<u8>`) each `KEY_SIZE` bytes long
    /// - `Err` — if HKDF expansion or underlying operations fail
    fn derive_keys(salt_cha: &[u8], salt_aes: &[u8], key: &SecretSlice<u8>) -> Result<(SecretSlice<u8>, SecretSlice<u8>)> {
        let key_cha = key_derivation(key, salt_cha, "xchacha20poly1305".as_bytes())?;
        let key_aes = key_derivation(key, salt_aes, "-aes-256-gcm-siv-".as_bytes())?;

        Ok((key_cha, key_aes))
    }

    /// Decrypts a buffer encrypted with XChaCha20-Poly1305 using the per‑chunk nonce modification.
    ///
    /// Extracts the nonce from the beginning of the buffer and decrypts the remainder
    /// using the provided key. Verifies authentication tag during decryption.
    /// The function reconstructs the modified nonce by XOR'ing:
    /// - `nonce[0]` with `final_chunk`, and
    /// - `nonce[1..]` with the little‑endian bytes of `chunk_count` (applied starting at index 1).
    /// 
    /// # Arguments
    /// - `key` — 32‑byte ChaCha key stored in a `SecretSlice<u8>`.
    /// - `buf`: Data containing nonce + ciphertext (+ authentication tag)
    /// - `chunk_count` — zero‑based chunk index; must match the value used during encryption.
    /// - `final_chunk` — `true` if this is the last chunk; must match the value used during encryption.
    ///
    /// # Returns
    /// - `Ok(plaintext)` containing decrypted data
    /// - `Err` if decryption fails or authentication tag verification fails
    pub fn cha_decrypt_buffer(key: &SecretSlice<u8>, buf: &[u8], chunk_count: u32, final_chunk: bool) -> Result<Vec<u8>> {
        let cipher = XChaCha20Poly1305::new_from_slice(key.expose_secret())
            .map_err(|e| format!("Failed to init decryption: {:?}", e))?;
        let mut nonce = *XNonce::from_slice(&buf[..CHA_NONCE_SIZE]);
        
        // change nonce by XOR of final chunk flag and chunk count
        nonce[0] ^= u8::from(final_chunk);
        for (i, ccb) in chunk_count.to_le_bytes().iter().enumerate() {
            nonce[i+1] ^= ccb;
        }

        let decrypted_buf = cipher.decrypt(&nonce, &buf[CHA_NONCE_SIZE..])
            .map_err(|e| format!("Failed to decrypt data: {:?}", e))?; 

        Ok(decrypted_buf)
    }

    /// Decrypts a buffer encrypted with AES-256-GCM-SIV.
    ///
    /// Extracts the nonce from the beginning of the buffer and decrypts the remainder
    /// using the provided key. Verifies authentication tag during decryption.
    ///
    /// # Arguments
    /// - `key`: 32‑byte AES key stored in a `SecretSlice<u8>`
    /// - `buf`: Data containing nonce + ciphertext (+ authentication tag)
    ///
    /// # Returns
    /// - `Ok(plaintext)` containing decrypted data
    /// - `Err` if decryption fails or authentication tag verification fails
    pub fn aes_decrypt_buffer(key: &SecretSlice<u8>, buf: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256GcmSiv::new_from_slice(key.expose_secret())
            .map_err(|e| format!("Failed to init decryption: {:?}", e))?;
        let nonce = Nonce::from_slice(&buf[..AES_NONCE_SIZE]);
        let decrypted_buf = cipher.decrypt(nonce, &buf[AES_NONCE_SIZE..])
            .map_err(|e| format!("Failed to decrypt data: {:?}", e))?; 

        Ok(decrypted_buf)
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
    /// - `key_cha`: ChaCha key used for inner decryption.
    /// - `key_aes`: AES key used for outer decryption.
    /// - `decompress`: enable resegment + decompression stages when true.
    /// - `rx_in`: receiver for encrypted input chunks `(data, chunk_count, final_flag)`.
    /// - `tx_out`: sender for final plaintext output `(plaintext_chunk, chunk_count)`.
    /// - `cpu_count`: number of worker threads to spawn.
    ///
    /// # Returns
    /// - `Vec<thread::JoinHandle<std::result::Result<(), String>>>` — handles for all spawned threads.
    pub fn decrypt_pipe(
        key_cha: &SecretSlice<u8>, 
        key_aes: &SecretSlice<u8>, 
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
            let key_cha = key_cha.clone();
            let key_aes = key_aes.clone();
            let rx_in = rx_in.clone();
            let tx_e = if decompress { tx_e.clone() } else { tx_out.clone() };

            thread_handles.push(thread::spawn( move || -> std::result::Result<(), String> { 
                for (buf_in, chunk_count, final_chunk) in rx_in {
                    let buf_aes = Self::aes_decrypt_buffer(&key_aes, &buf_in).map_err(|e| e.to_string())?;
                    let buf_cha = Self::cha_decrypt_buffer(&key_cha, &buf_aes, chunk_count, final_chunk).map_err(|e| e.to_string())?;
                    if tx_e.send((buf_cha, chunk_count)).is_err() { break }
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

    /// Decrypts a file encrypted with dual-layer encryption (AES-256-GCM-SIV + ChaCha20).
    ///
    /// Reads and evaluates header from file, prompts user for password, derives master key using Argon2,
    /// derives keys for ChaCha20 and AES-256-GCM-SIV, decrypts the file in chunks across multiple threads. 
    /// Output file has `.cce` suffix removed.
    ///
    /// # Arguments
    /// - `filepath_in`: Path to encrypted input file (must end with `.cce`)
    /// - `keyfilepath`: Optional path to an additional key file
    ///
    /// # Returns
    /// - `Ok(())` on successful decryption
    /// - `Err` if file operations, password handling, or decryption fails
    pub fn decrypt(filepath_in: &PathBuf, keyfilepath: Option<&PathBuf>) -> Result<()> {
        if filepath_in.is_dir() {
            return Err("Cannot decrypt a directory".into());
        }

        let mut filepath_out = filepath_in.clone();
        if filepath_in.extension() == Some(std::ffi::OsStr::new(ENCRYPTED_FILE_EXT)) ||
           filepath_in.extension() == Some(std::ffi::OsStr::new(SPLIT_ENC_FILE_EXT)) {
            // remove encrypted-file-extension
            filepath_out.set_extension("");
        } else {
            return Err(format!("Invalid filename, it does not end with .{ENCRYPTED_FILE_EXT} or .{SPLIT_ENC_FILE_EXT}").into())
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

        let file_format_version = header[0];
        let file_format         = header[1];
        let salt_pw          = &header[2..34];
        let salt_cha         = &header[34..66];
        let salt_aes         = &header[66..98];
        
        // check format version
        if file_format_version != FILE_FORMAT_VERSION {
            return Err(format!(
                "This input file format (v{file_format_version}) cannot be decoded with this app version. It requires file format v{FILE_FORMAT_VERSION}."
            ).into());
        }

        // get keys
        let key = Self::hash_password(salt_pw, keyfilepath)?;
        let (key_cha, key_aes) = Self::derive_keys(salt_cha, salt_aes, &key)?;

        let compress = (file_format & 0x01) != 0;
        let archive  = (file_format & 0x02) != 0;

        let write_output: Box<dyn WriteFiles + Send + 'static> = if archive {
            Box::new( ArchiveWrite::new() )
        } else {
            // set write parameters and create output file
            Box::new( WriteOutput::new(filepath_out, vec![])? )
        };

        CryptIo::io_chunks(&key_cha, &key_aes, compress, Self::decrypt_pipe, read_input, write_output)?;

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