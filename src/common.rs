use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::thread;
use rpassword::{prompt_password, read_password_from_bufread};
use std::io::Cursor;
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use sha3::Sha3_512;
use secrecy::{ExposeSecret, ExposeSecretMut, SecretSlice, SecretString};

use crate::*;


/// Prompts the user to enter a password from the terminal.
///
/// In test mode, returns a hardcoded test password. In normal mode, reads a password
/// from user input, optionally verifying it matches a repeated entry.
///
/// # Arguments
/// - `verify`: If `true`, prompts the user to repeat the password and verifies they match.
///   If `false`, only prompts once.
///
/// # Returns
/// - `Ok(password)` containing the user's password
/// - `Err` if passwords don't match (when verify=true) or on I/O error
fn get_password_from_user(verify: bool) -> Result<SecretString> {
    if cfg!(test) {
        println!("!!! Test-password used !!!");
    }

    let password = SecretString::from(
        if cfg!(test) {
            read_password_from_bufread(&mut Cursor::new("abc123test\n"))?
        } else {
            prompt_password("Enter password: ")?
        }
    );

    
    if verify {
        let password_rep = SecretString::from( 
            if cfg!(test) {
                read_password_from_bufread(&mut Cursor::new("abc123test\n"))?
            } else {
                prompt_password("Repeat password: ")? 
            }
        );

        if password.expose_secret() != password_rep.expose_secret() {
            return Err("Passwords do not match!".into());
        }
    }

    Ok(password)
}

/// Reads and hashes a key file using SHA3-512.
///
/// Opens the key file and reads it in chunks (up to MAX_KEYFILE_CHUNKS chunks of CHUNK_SIZE 
/// bytes each, i.e. max. 64 MB), updating a SHA3-512 hasher with each chunk. Returns the final 
/// hash as a 64-byte array. If the file is smaller than the chunk buffer, it stops reading when 
/// EOF is reached.
///
/// # Arguments
/// - `keyfilepath`: Path to the key file to read and hash
///
/// # Returns
/// - `Ok(hash)` containing the SHA3-512 hash
/// - `Err` if the file cannot be opened or read
fn read_and_hash_keyfile(keyfilepath: &PathBuf) -> Result<[u8; 64]> {
    let mut f_in  = File::open(keyfilepath)?;
    let mut buf_in = vec![0u8; CHUNK_SIZE];
    let mut hasher = Sha3_512::new();

    let mut count_chunks = MAX_KEYFILE_CHUNKS;
    while count_chunks > 0 {
        let count_in = f_in.read(&mut buf_in)?;
        if count_in == 0 { 
            break;
        }
        hasher.update(&buf_in[..count_in]);
        count_chunks -= 1;
    }

    let hash = hasher.finalize();
    Ok(hash.into())
}

/// Retrieves and combines password and optional key file hash into secret bytes.
///
/// Reads and hashes the optional key file first (before prompting for password),
/// then prompts the user for a password and concatenates the password bytes with
/// the key file hash. Returns the combined data.
///
/// # Arguments
/// - `keyfilepath`: Optional path to a key file to hash and append
/// - `verify_password`: If `true`, prompts user to repeat password and verifies they match.
///   If `false`, only prompts once.
///
/// # Returns
/// - `Ok(pass_bytes)` containing concatenated password and key file hash
/// - `Err` if key file reading fails, password entry fails, or passwords don't match (when verify=true)
pub fn get_pass_bytes(keyfilepath: Option<&PathBuf>, verify_password: bool) -> Result<SecretSlice<u8>> {
    // read keyfile, if passed by user
    // as that might fail, it is done before password is entered and then is available in memory
    let mut hash= vec![];
    if let Some(keyfile) = keyfilepath {
        hash.extend(read_and_hash_keyfile(keyfile)?);
    }

    // get password string and append hash
    let password = get_password_from_user(verify_password)?;
    let pass_bytes = SecretSlice::from([password.expose_secret().as_bytes(), &hash].concat());

    Ok(pass_bytes)
}

/// Derives output key material (OKM) using HKDF-SHA256.
///
/// HKDF (HMAC-based Key Derivation Function) expands a pseudo-random key (PRK)
/// into a derived key of specified length using provided info bytes.
///
/// # Arguments
/// - `key`: The pseudo-random key (PRK) for HKDF with length 32. 
/// - `salt`: Salt bytes
/// - `info`: Information bytes for HKDF expand phase.
///
/// # Returns
/// - `Ok(okm)` output key material
/// - `Err` if PRK length is invalid or requested output length is invalid
pub fn key_derivation(key: &SecretSlice<u8>, salt: &[u8], info: &[u8]) -> Result<SecretSlice<u8>> {
    let hk = Hkdf::<Sha256>::new(Some(salt), key.expose_secret());
    let mut okm = SecretSlice::from(vec![0u8; KEY_SIZE]);
    hk.expand(info, okm.expose_secret_mut())
        .map_err(|e| format!("Invalid length for HKDF expand: {:?}", e))?;
    Ok(okm)
}

/// Parameters for file operations during cryptographic processing.
pub struct CryptIo {
    /// Input file to read data from
    f_in: File, 
    /// Output file to write processed data to
    f_out: File,
    /// Total size in bytes of input data remaining to be read
    f_in_size_remaining: u64, 
    /// Size in bytes of each chunk to process per iteration
    chunk_size: usize,
    /// Compress data before encryption
    compress: bool,
}

impl CryptIo {

    pub fn new(f_in: File, f_out: File, f_in_size_remaining: u64, chunk_size: usize, compress: bool) -> Self {
        Self { f_in, f_out, f_in_size_remaining, chunk_size, compress }
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
            // dynamic chunk size (if compression is used)
            let mut buf = [0u8; AES_LENGTH_SIZE];
            self.f_in.read_exact(&mut buf)?;
            self.f_in_size_remaining -= buf.len() as u64;
            let c_size: [u8; 4] = [&buf[..], &[0]].concat().try_into().unwrap();
            u32::from_le_bytes(c_size)
        } else {
            // fixed chunk size
            u32::try_from(self.chunk_size)?
        };

        let (read_size, final_chunk) = 
            if self.f_in_size_remaining <= u64::from(cuk_size) {
                // final chunk
                (u32::try_from(self.f_in_size_remaining)?, true)
            } else {
                (cuk_size, false)
            };

        self.f_in_size_remaining -= u64::from(read_size);

        Ok((read_size as usize, final_chunk))
    }

    /// Performs cryptographic I/O operations on a file using chunked processing with multithreading.
    ///
    /// Reads input file in chunks, applies two sequential cryptographic functions to each chunk
    /// using parallelism by threads and writes the results.
    ///
    /// # Arguments
    /// - `fp`: file parameters
    /// - `key1`: Cryptographic key for processing with first cryptographic function
    /// - `key2`: Cryptographic key for processing with second cryptographic function
    /// - `crypt_fn1`: First cryptographic function (e.g., first-pass encryption)
    /// - `crypt_fn2`: Second cryptographic function (e.g., second-pass encryption)
    ///
    /// # Returns
    /// - `Ok(())` on successful completion
    /// - `Err` if file I/O fails or cryptographic functions fail
    #[allow(clippy::type_complexity)]
    pub fn io_chunks(
        &mut self,
        key_cha: &SecretSlice<u8>, 
        key_aes: &SecretSlice<u8>,
        crypt_fn: fn(&SecretSlice<u8>, &SecretSlice<u8>, &[u8], u32, bool, bool) -> Result<Vec<u8>>
    ) -> Result<()> 
    {
        let cpu_count = num_cpus::get();
        let mut chunk_count: u32 = 0;  
        let compress = self.compress;

        while self.f_in_size_remaining > 0 {
            let mut child_threads = Vec::with_capacity(cpu_count);

            for _ in 0..cpu_count {
                let key_cha = key_cha.clone();
                let key_aes = key_aes.clone();

                let (read_size, final_chunk) = self.input_sizes()?;

                let mut buf_in = vec![0u8; read_size];
                self.f_in.read_exact(&mut buf_in)?;

                child_threads.push(thread::spawn(move || {
                        let buf_out = crypt_fn(&key_cha, &key_aes, &buf_in, chunk_count, final_chunk, compress)
                            .map_err(|e| e.to_string())?;
                        Ok::<Vec<u8>, String>(buf_out)
                    }));
                
                if self.f_in_size_remaining == 0 {
                    break;
                } 
                chunk_count += 1;
            }

            for child in child_threads {
                let buf_out = child.join().unwrap()?;
                self.f_out.write_all(&buf_out)?;
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
    use rand::Rng;

    #[test]
    fn test_get_password_from_user() {
        let pw = get_password_from_user(false).unwrap();
        assert_eq!("abc123test", pw.expose_secret());

        let pw = get_password_from_user(true).unwrap();
        assert_eq!("abc123test", pw.expose_secret());
    }

    #[test]
    fn test_read_and_hash_keyfile() {
        // create a key file
        let filepath_kf = PathBuf::from("test_key_rh.bin");
        let mut data_kf = vec![0; 100];
        rand::rng().fill_bytes(&mut data_kf);
        fs::write(&filepath_kf, data_kf).unwrap();

        // repeated read should return the same hash which should not be all zeros
        let hash1 = read_and_hash_keyfile(&filepath_kf).unwrap();
        let hash2 = read_and_hash_keyfile(&filepath_kf).unwrap();
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, [0u8; 64]);

        // empty file
        let data_kf = [];
        fs::write(&filepath_kf, data_kf).unwrap();
        let hash1 = read_and_hash_keyfile(&filepath_kf).unwrap();
        let hash2 = read_and_hash_keyfile(&filepath_kf).unwrap();
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, [0u8; 64]);

        // big file
        let data_kf = vec![0xa5; MAX_KEYFILE_CHUNKS * CHUNK_SIZE];
        fs::write(&filepath_kf, data_kf).unwrap();
        let hash1 = read_and_hash_keyfile(&filepath_kf).unwrap();
        let hash2 = read_and_hash_keyfile(&filepath_kf).unwrap();
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, [0u8; 64]);

        // more than chunk size
        let mut data_kf = vec![0; CHUNK_SIZE + 10];
        rand::rng().fill_bytes(&mut data_kf);
        fs::write(&filepath_kf, data_kf).unwrap();
        let hash1 = read_and_hash_keyfile(&filepath_kf).unwrap();
        let hash2 = read_and_hash_keyfile(&filepath_kf).unwrap();
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, [0u8; 64]);

        // key file does not exist
        assert!(read_and_hash_keyfile(&PathBuf::from("test_miss")).is_err());

        // cleanup
        let _ = fs::remove_file(&filepath_kf);
    }

    #[test]
    fn test_get_pass_bytes() {
        // no key file
        let pass = get_pass_bytes(None, false).unwrap();
        assert_eq!("abc123test".as_bytes(), pass.expose_secret());

        // with key file
        let filepath_kf = PathBuf::from("test_gpb.bin");
        let data_kf = [0xa5; 50];
        fs::write(&filepath_kf, data_kf).unwrap();
        let pass = get_pass_bytes(Some(&filepath_kf), false).unwrap();
        assert!(pass.expose_secret().starts_with("abc123test".as_bytes()));
        assert_eq!(pass.expose_secret().len(), "abc123test".len() + 64);

        // key file does not exist
        assert!(get_pass_bytes(Some(&PathBuf::from("test_miss")), false).is_err());

        // cleanup
        let _ = fs::remove_file(&filepath_kf);
    }

    #[test]
    fn test_key_derivation() {
        let key: [u8; KEY_SIZE] = rand::random();
        let key_sec = SecretSlice::from(key.to_vec());
        let salt: [u8; SALT_SIZE] = rand::random();
        let info = [0xa; 12];

        // output shouldn't change if called again
        let okm1 = key_derivation(&key_sec, &salt, &info).unwrap();
        let okm2 = key_derivation(&key_sec, &salt, &info).unwrap();
        assert_eq!(okm1.expose_secret(), okm2.expose_secret());
        assert_eq!(okm1.expose_secret().len(), KEY_SIZE);
        assert_ne!(okm1.expose_secret(), [0; KEY_SIZE]);
        assert_ne!(okm1.expose_secret(), key);

        // different output on different info input
        let info = [0xb; 12];
        let okm3 = key_derivation(&key_sec, &salt, &info).unwrap();
        assert_ne!(okm1.expose_secret(), okm3.expose_secret());

        // different output on different info input
        let mut salt4 = salt;
        salt4[0] ^= 0xFF;
        let okm4 = key_derivation(&key_sec, &salt4, &info).unwrap();
        assert_ne!(okm3.expose_secret(), okm4.expose_secret());

        // different output on different key input
        let mut key4 = key;
        key4[0] ^= 0x01;
        let okm5 = key_derivation(&SecretSlice::from(key4.to_vec()), &salt4, &info).unwrap();
        assert_ne!(okm4.expose_secret(), okm5.expose_secret());

        // Even empty salt, should produce a valid non-zero key
        let salt6= [];
        let okm6 = key_derivation(&key_sec, &salt6, &info).unwrap();
        assert_ne!(okm6.expose_secret(), [0u8; KEY_SIZE]);
        assert_ne!(okm1.expose_secret(), okm6.expose_secret());
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
        let decrypt_data = Decryption::aes_decrypt_buffer(&key, &encrypt_data[3..]).unwrap();
        assert_eq!(encrypt_data.len(), data.len() + AES_LENGTH_SIZE + AES_NONCE_SIZE + AES_TAG_SIZE);
        assert_eq!(data, decrypt_data[..]);

        // second encryption must produce different output of the same input
        let encrypt_data2 = Encryption::aes_encrypt_buffer(&key, &data).unwrap();
        // nonce part must be different
        assert_ne!(encrypt_data[AES_LENGTH_SIZE..AES_LENGTH_SIZE + AES_NONCE_SIZE], encrypt_data2[AES_LENGTH_SIZE..AES_LENGTH_SIZE + AES_NONCE_SIZE]);
        // encrypted data part must be different
        assert_ne!(encrypt_data[3 + AES_NONCE_SIZE..], encrypt_data2[3 + AES_NONCE_SIZE..]);

        // corrupt 'nonce'
        let mut bad_data = encrypt_data.clone();
        bad_data[AES_LENGTH_SIZE+1] ^= 0xFF;
        assert!(Decryption::aes_decrypt_buffer(&key, &bad_data).is_err());

        // corrupt 'data'
        let mut bad_data = encrypt_data.clone();
        bad_data[AES_LENGTH_SIZE + AES_NONCE_SIZE + 1] ^= 0xFF;
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

        
        let mut data = vec![0; 1024 * 3000];
        rand::rng().fill_bytes(&mut data);
        fs::write(&filepath_in, &data).unwrap();

        assert_eq!(get_password_from_user(false).unwrap().expose_secret(), "abc123test");

        // encrypt, backup original file, decrypt
        Encryption::encrypt(&filepath_in, None, false).unwrap();
        // encrypted file must be different than original data
        assert_ne!(data, fs::read(&filepath_out).unwrap());
        // backup by renaming
        fs::rename(&filepath_in, &filepath_org).unwrap();
        Decryption::decrypt(&filepath_out, None).unwrap();

        // read and compare decrypted file against backup
        let decrypt_data = fs::read(&filepath_in).unwrap();
        assert_eq!(data, decrypt_data[..]);

        // decrypt with keyfile
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
        Encryption::encrypt(&filepath_in, Some(&filepath_kf), false).unwrap();
        fs::rename(&filepath_in, &filepath_org).unwrap();
        Decryption::decrypt(&filepath_out, Some(&filepath_kf)).unwrap();

        // read and compare decrypted file against backup
        let decrypt_data = fs::read(&filepath_in).unwrap();
        assert_eq!(data, decrypt_data[..]);

        // decrypt without key file
        assert!(Decryption::decrypt(&filepath_out, None).is_err());

        // key file does not exist
        assert!(Encryption::encrypt(&filepath_in, Some(&PathBuf::from("test_miss")), false).is_err());
        assert!(Decryption::decrypt(&filepath_out, Some(&PathBuf::from("test_miss"))).is_err());

        // input file does not exist
        assert!(Encryption::encrypt(&PathBuf::from("test_miss"), None, false).is_err());
        assert!(Decryption::decrypt(&PathBuf::from("test_miss"), None).is_err());

        // cleanup
        let _ = fs::remove_file(&filepath_in);
        let _ = fs::remove_file(&filepath_out);
        let _ = fs::remove_file(&filepath_org);
        let _ = fs::remove_file(&filepath_kf);
    }

    #[test]
    #[ignore="only for benchmarking"]
    fn test_crypt_bench() {
        // a file 'ttt' must already exist
        let filepath_in = PathBuf::from("ttt");     
        let mut filepath_out = filepath_in.clone();
        filepath_out.add_extension(ENCRYPTED_FILE_EXT);

        Encryption::encrypt(&filepath_in, None, false).unwrap();
        Decryption::decrypt(&filepath_out, None).unwrap();
    }
}