use std::io::Read;
use std::path::{Path, PathBuf};
use argon2::Argon2;
use chacha20poly1305::{XChaCha20Poly1305};
use rand::{Rng, SeedableRng};
use rand::rngs::SysRng;
use rand_chacha::ChaCha20Rng;
use aes_gcm_siv::{aead::{Aead, KeyInit, OsRng}, Aes256GcmSiv, AeadCore};
use secrecy::{ExposeSecret, ExposeSecretMut, SecretSlice};
use bzip2::Compression;
use bzip2::read::BzEncoder;

use crate::*;
use crate::common::{get_pass_bytes, key_derivation};
use crate::common_io::{CryptIo, ReadInput, WriteOutput};


/// Handles file encryption operations using dual-layer encryption.
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
    ///   (applied starting at index 1).
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
    /// - `Err(...)` if initialization or encryption fails.
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

        let encrypted_buf = cipher.encrypt(&nonce, buf)
            .map_err(|e| format!("Failed to encrypt data: {:?}", e))?;
        let combined_data = [&nonce_org[..], &encrypted_buf[..]].concat();
        
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
    /// - `Ok(encrypted_data)` containing  buffer length + nonce + ciphertext (+ authentication tag)
    /// - `Err` if key derivation or encryption fails
    pub fn aes_encrypt_buffer(key: &SecretSlice<u8>, buf: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256GcmSiv::new_from_slice(key.expose_secret())
            .map_err(|e| format!("Failed to init encryption: {:?}", e))?;
        let nonce =  Aes256GcmSiv::generate_nonce(OsRng);
        let encrypted_buf = cipher.encrypt(&nonce, buf)
            .map_err(|e| format!("Failed to encrypt data: {:?}", e))?;

        let combined_len = (nonce.len() + encrypted_buf.len()).to_le_bytes();
        let combined_data = [&combined_len[..AES_LENGTH_SIZE], &nonce[..], &encrypted_buf[..]].concat();

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
        let mut compressed_data = Vec::with_capacity(CHUNK_SIZE);
        compressor.read_to_end(&mut compressed_data)?;
        Ok(compressed_data)
    }

    /// Process a plaintext chunk through compression (optional), ChaCha20, then AES.
    ///
    /// This function is the per-chunk pipeline used during encryption: it
    /// optionally compresses the input chunk, encrypts it with XChaCha20-Poly1305,
    /// then encrypts the result with AES-256-GCM-SIV. The returned buffer has a
    /// 3‑byte little-endian length prefix followed by the AES output (nonce + ciphertext + tag).
    ///
    /// # Arguments
    /// - `key_cha`: ChaCha key for first-layer encryption
    /// - `key_aes`: AES key for second-layer encryption
    /// - `buf_in`: plaintext input bytes for this chunk
    /// - `chunk_count`: zero-based index of the chunk
    /// - `final_chunk`: whether this is the last chunk
    /// - `compress`: whether to compress the plaintext before encryption
    ///
    /// # Returns
    /// - `Ok(out_buf)` containing AES output
    /// - `Err` on compression or encryption failure
    pub fn encrypt_pipe(key_cha: &SecretSlice<u8>, key_aes: &SecretSlice<u8>, buf_in: &[u8], chunk_count: u32, final_chunk: bool, compress: bool) -> Result<Vec<u8>> {
        let buf_zip = if compress {
            &Self::compress_buffer(buf_in)?
        } else {
            buf_in
        };
        let buf_cha = Self::cha_encrypt_buffer(key_cha, buf_zip, chunk_count, final_chunk)?;
        let buf_aes = Self::aes_encrypt_buffer(key_aes, &buf_cha)?;

        Ok(buf_aes)
    }

    /// Encrypts a file using dual-layer encryption (ChaCha20 + AES-256-GCM-SIV).
    ///
    /// Prompts user for password, derives master key using Argon2, derives keys for 
    /// ChaCha20 and AES-256-GCM-SIV, compresses (on demand) and encrypts the file in
    /// chunks across multiple threads. Output file gets `.cce` extension. Or output can 
    /// be split into several files, which get extensions `.c00`, `.c01`, `.c02`, ...
    /// 
    /// # Arguments
    /// - `filepath_in`: Path to input file to encrypt
    /// - `keyfilepath`: Optional path to an additional key file
    /// - `compress`: Compress input file before encryption
    /// - `split`: List of output split sizes; if empty, no split is done.
    ///
    /// # Returns
    /// - `Ok(())` on successful encryption
    /// - `Err` if file operations, password handling, or encryption fails
    pub fn encrypt(filepath_in: &Path, keyfilepath: Option<&PathBuf>, compress: bool, split: Vec<u64>) -> Result<()> {
        let mut filepath_out = filepath_in.to_path_buf();
        if split.is_empty() {
            filepath_out.add_extension(ENCRYPTED_FILE_EXT);
        } else {
            filepath_out.add_extension(SPLIT_ENC_FILE_EXT);
        }

        let (salt_pw, key) = Self::hash_password(keyfilepath)?;
        let (salt_cha, key_cha, salt_aes, key_aes) = Self::derive_keys(&key)?;

        // file header
        //   byte  description
        //      0  version of file format
        //      1  info about file format
        //           bit 0: compression on(1)/off(0)
        //  2..33  32-byte-salt of password hash
        // 34..65  32-byte-salt of cha key derivation
        // 66..97  32-byte-salt of aes key derivation
        let mut header = Vec::with_capacity(HEADER_SIZE);
        header.push(FILE_FORMAT_VERSION);
        header.push(u8::from(compress));
        header.extend(salt_pw);
        header.extend(salt_cha);
        header.extend(salt_aes);

        // set read parameters
        let read_input = ReadInput::new(filepath_in.to_path_buf(), CHUNK_SIZE, 0)?;

         // set write parameters and create output file
        let mut write_output = WriteOutput::new(filepath_out, split)?;

        // write header
        write_output.write_files(&header)?;

        // set crypto parameters
        let mut cio = CryptIo::new (
            read_input,
            write_output,
        );

        cio.io_chunks(&key_cha, &key_aes, compress, Self::encrypt_pipe)?;

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
    fn test_crypt_pipe() {
        let key_cha: [u8; 32]  = rand::random();
        let key_cha = SecretSlice::from(key_cha.to_vec());
        let key_aes: [u8; 32]  = rand::random();
        let key_aes = SecretSlice::from(key_aes.to_vec());
        let data: [u8; 100] = rand::random();

        // with compression
        let out_enc = Encryption::encrypt_pipe(&key_cha, &key_aes, &data, 10, false, true).unwrap();
        let out_dec = Decryption::decrypt_pipe(&key_cha, &key_aes, &out_enc[3..], 10, false, true).unwrap();
        assert_eq!(data, &out_dec[..]);
        // check length info in encrypted data
        let size: [u8; 4] = [&out_enc[..3], &[0]].concat().try_into().unwrap();
        assert_eq!(u32::from_le_bytes(size), out_enc[3..].len() as u32);

        // without compression
        let out_enc = Encryption::encrypt_pipe(&key_cha, &key_aes, &data, 10, false, false).unwrap();
        let out_dec = Decryption::decrypt_pipe(&key_cha, &key_aes, &out_enc[3..], 10, false, false).unwrap();
        assert_eq!(data, &out_dec[..]);
        // check length info in encrypted data
        let size: [u8; 4] = [&out_enc[..3], &[0]].concat().try_into().unwrap();
        assert_eq!(u32::from_le_bytes(size), out_enc[3..].len() as u32);
    }

    #[test]
    fn test_crypt() {
        // create file with random data for encryption
        let filepath_in = PathBuf::from("test_cc.bin");
        let mut filepath_out = filepath_in.clone();
        filepath_out.add_extension(ENCRYPTED_FILE_EXT);
        let mut filepath_org = filepath_in.clone();
        filepath_org.add_extension("org");

        // create random input file
        let mut data = vec![0; 1024 * 3000];
        rand::rng().fill_bytes(&mut data);
        fs::write(&filepath_in, &data).unwrap();

        // encrypt, backup original file, decrypt
        Encryption::encrypt(&filepath_in, None, false, vec![]).unwrap();
        // encrypted file must be different than original data
        assert_ne!(data, fs::read(&filepath_out).unwrap());
        // backup by renaming
        fs::rename(&filepath_in, &filepath_org).unwrap();
        Decryption::decrypt(&filepath_out, None).unwrap();

        // read and compare decrypted file against backup
        let decrypt_data = fs::read(&filepath_in).unwrap();
        assert_eq!(data, decrypt_data[..]);

        // decrypt with keyfile should fail
        let filepath_kf = PathBuf::from("test_another_key.bin");
        fs::write(&filepath_kf, vec![0; 1024]).unwrap();
        assert!(Decryption::decrypt(&filepath_out, Some(&filepath_kf)).is_err());

        // cleanup
        let _ = fs::remove_file(&filepath_in);
        let _ = fs::remove_file(&filepath_out);
        let _ = fs::remove_file(&filepath_org);
        let _ = fs::remove_file(&filepath_kf);
    }

     #[test]
    fn test_crypt_with_keyfile() {
        // create file with random data for encryption
        let filepath_in = PathBuf::from("test_cc_kf.bin");
        let mut filepath_out = filepath_in.clone();
        filepath_out.add_extension(ENCRYPTED_FILE_EXT);
        let mut filepath_org = filepath_in.clone();
        filepath_org.add_extension("org");
        let filepath_kf = PathBuf::from("test_key.bin");
        
        let mut data = vec![0; 1024 * 1024];
        rand::rng().fill_bytes(&mut data);
        fs::write(&filepath_in, &data).unwrap();

        let mut data_kf = vec![0; 1024 * 1024 * 2];
        rand::rng().fill_bytes(&mut data_kf);
        fs::write(&filepath_kf, &data_kf).unwrap();

        // use keyfile, encrypt, backup original file, decrypt
        Encryption::encrypt(&filepath_in, Some(&filepath_kf), false, vec![]).unwrap();
        fs::rename(&filepath_in, &filepath_org).unwrap();
        Decryption::decrypt(&filepath_out, Some(&filepath_kf)).unwrap();

        // read and compare decrypted file against backup
        let decrypt_data = fs::read(&filepath_in).unwrap();
        assert_eq!(data, decrypt_data[..]);

        // decrypt without key file
        assert!(Decryption::decrypt(&filepath_out, None).is_err());

        // key file does not exist
        assert!(Encryption::encrypt(&filepath_in, Some(&PathBuf::from("test_miss")), false, vec![]).is_err());
        assert!(Decryption::decrypt(&filepath_out, Some(&PathBuf::from("test_miss"))).is_err());

        // input file does not exist
        assert!(Encryption::encrypt(&PathBuf::from("test_miss"), None, false, vec![]).is_err());
        assert!(Decryption::decrypt(&PathBuf::from("test_miss"), None).is_err());

        // cleanup
        let _ = fs::remove_file(&filepath_in);
        let _ = fs::remove_file(&filepath_out);
        let _ = fs::remove_file(&filepath_org);
        let _ = fs::remove_file(&filepath_kf);
    }

    #[test]
    fn test_crypt_split() {
        let filepath_in = PathBuf::from("test_cc_split.bin");
        let mut filepath_out = filepath_in.clone();
        filepath_out.add_extension(ENCRYPTED_FILE_EXT);
        let mut filepath_org = filepath_in.clone();
        filepath_org.add_extension("org");

        // create random input file
        let mut data = vec![0; 1024 * 3000];
        rand::rng().fill_bytes(&mut data);
        fs::write(&filepath_in, &data).unwrap();

        Encryption::encrypt(&filepath_in, None, false, vec![1048576, 12]).unwrap();
        // backup by renaming
        fs::rename(&filepath_in, &filepath_org).unwrap();

        // concatenate spilt output files
        let mut data_concat = fs::read("test_cc_split.bin.c00").unwrap();
        data_concat.extend(fs::read("test_cc_split.bin.c01").unwrap());
        data_concat.extend(fs::read("test_cc_split.bin.c02").unwrap());
        fs::write(&filepath_out, &data_concat).unwrap();

        Decryption::decrypt(&filepath_out, None).unwrap();
        // read and compare decrypted file against backup
        let decrypt_data = fs::read(&filepath_in).unwrap();
        assert_eq!(data, decrypt_data[..]);

        // concatenate files with decrypt
        let _ = fs::remove_file(&filepath_in);
        let _ = fs::remove_file(&filepath_out);
        Decryption::decrypt(&PathBuf::from("test_cc_split.bin.c00"), None).unwrap();
        // read and compare decrypted file against backup
        let decrypt_data = fs::read(&filepath_in).unwrap();
        assert_eq!(data, decrypt_data[..]);


        // cleanup
        let _ = fs::remove_file(&filepath_in);
        let _ = fs::remove_file(&filepath_out);
        let _ = fs::remove_file(&filepath_org);
        let _ = fs::remove_file("test_cc_split.bin.c00");
        let _ = fs::remove_file("test_cc_split.bin.c01");
        let _ = fs::remove_file("test_cc_split.bin.c02");
    }

    #[test]
    #[ignore="only for benchmarking"]
    fn test_crypt_bench() {
        // a file 'ttt' must already exist
        let filepath_in = PathBuf::from("ttt");     
        let mut filepath_out = filepath_in.clone();
        filepath_out.add_extension(ENCRYPTED_FILE_EXT);

        Encryption::encrypt(&filepath_in, None, false, vec![]).unwrap();
        Decryption::decrypt(&filepath_out, None).unwrap();
    }
}