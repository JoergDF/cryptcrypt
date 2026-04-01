use std::fs::File;
use std::io::{Read, Write};
use std::error::Error;
use std::path::PathBuf;
use std::thread;
use argon2::Argon2;
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::{Rng, SeedableRng};
use rand::rngs::SysRng;
use rand_chacha::ChaCha20Rng;
use aes_gcm_siv::{
    aead::{rand_core::RngCore, Aead, KeyInit, OsRng}, 
    Aes256GcmSiv, AeadCore, Nonce
};
use typenum::Unsigned;
use clap::Parser;
use rpassword::{prompt_password, read_password_from_bufread};
use std::io::Cursor;
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use sha3::Sha3_512;
use secrecy::{ExposeSecret, ExposeSecretMut, SecretSlice, SecretString};


const ENCRYPTED_FILE_EXT: &str  = "cce";
const CHUNK_SIZE: usize         = 1024 * 1024;
const MAX_KEYFILE_CHUNKS: usize = 64;
const PW_SALT_SIZE: usize       = 32; 
const KEY_SIZE: usize           = 32; 
const AES_NONCE_SIZE: usize     = <Aes256GcmSiv as AeadCore>::NonceSize::USIZE; 
const AES_TAG_SIZE: usize       = <Aes256GcmSiv as AeadCore>::TagSize::USIZE;
const CHA_NONCE_SIZE: usize     = <XChaCha20Poly1305 as AeadCore>::NonceSize::USIZE; 
const CHA_TAG_SIZE: usize       = <XChaCha20Poly1305 as AeadCore>::TagSize::USIZE;
const HKDF_INFO_SIZE: usize     = 12; 

type Result<T> = std::result::Result<T, Box<dyn Error>>;


/// Program for encryption and decryption of a file. 
/// If no option is given, file is encrypted.
#[derive(Parser)]
#[command(version, about, verbatim_doc_comment, long_about = None)]
struct Args {
    /// Decrypt file
    #[arg(short, long, default_value_t = false)]
    decrypt: bool,

    /// Additional key file to supplement the password
    #[arg(short, long)]
    keyfile: Option<PathBuf>,

    /// File that should be encrypted or decrypted
    file: PathBuf,
}

/// Main entry point for the cryptcrypt application.
///
/// Parses command-line arguments and dispatches to either encryption or decryption
/// based on the provided flags.
///
/// # Returns
/// - `Ok(())` on successful completion
/// - `Err` if an error occurs during encryption/decryption
fn main() -> Result<()> {
    let args = Args::parse();

    let filepath = args.file;
    let keyfilepath = args.keyfile;

    if args.decrypt {
       Decryption::decrypt(&filepath, keyfilepath.as_ref())?;
    } else {
       Encryption::encrypt(&filepath, keyfilepath.as_ref())?;
    }

    Ok(())
}

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
fn get_pass_bytes(keyfilepath: Option<&PathBuf>, verify_password: bool) -> Result<SecretSlice<u8>> {
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
/// - `key`: The pseudo-random key (PRK) for HKDF with length 32. Caller must ensure high entropy.
/// - `info`: Information bytes for HKDF expand phase.
///
/// # Returns
/// - `Ok(okm)` output key material
/// - `Err` if PRK length is invalid or requested output length is invalid
fn key_derivation(key: &SecretSlice<u8>, info: &[u8]) -> Result<SecretSlice<u8>> {
    let hk = Hkdf::<Sha256>::from_prk(key.expose_secret())
        .map_err(|e| format!("Invalid PRK length for HKDF: {:?}", e))?;
    let mut okm = SecretSlice::from(vec![0u8; KEY_SIZE]);
    hk.expand(info, okm.expose_secret_mut())
        .map_err(|e| format!("Invalid length for HKDF expand: {:?}", e))?;
    Ok(okm)
}


/// Performs cryptographic I/O operations on a file using chunked processing with multithreading.
///
/// Reads input file in chunks, applies two sequential cryptographic functions to each chunk
/// using thread-level parallelism (one thread per CPU core), and writes the results.
///
/// # Arguments
/// - `f_in`: Input file to process
/// - `f_out`: Output file to write results
/// - `chunk_size`: Size of data chunk to process per read operation
/// - `key`: Cryptographic key for processing (will be cloned for each thread)
/// - `crypt_fn1`: First cryptographic function (e.g., first-pass encryption)
/// - `crypt_fn2`: Second cryptographic function (e.g., second-pass encryption)
///
/// # Returns
/// - `Ok(())` on successful completion
/// - `Err` if file I/O fails or cryptographic functions fail
fn crypt_io(mut f_in: File, mut f_out: File, chunk_size: usize, key: &SecretSlice<u8>, 
    crypt_fn1: fn(&SecretSlice<u8>, &[u8]) -> Result<Vec<u8>>,
    crypt_fn2: fn(&SecretSlice<u8>, &[u8]) -> Result<Vec<u8>>) 
    -> Result<()> 
{
    let cpu_count = num_cpus::get();
       
    // Read in chunks from file 
    let buf_in = vec![0u8; chunk_size];

    let mut run_loop = true;
    while run_loop {
        let mut child_threads = Vec::with_capacity(cpu_count);

        for _ in 0..cpu_count {
            let mut buf_in = buf_in.clone();
            let key = key.clone();

            let count_in = f_in.read(&mut buf_in)?;
            if count_in == 0 { 
                run_loop = false;
                break;
            }

            child_threads.push(thread::spawn(move || {
                    let buf_tmp = crypt_fn1(&key, &buf_in[..count_in])
                        .map_err(|e| e.to_string())?;
                    let buf_out = crypt_fn2(&key, &buf_tmp)
                        .map_err(|e| e.to_string())?;
                    Ok::<Vec<u8>, String>(buf_out)
                }));
        }

        for child in child_threads {
            let buf_out = child.join().unwrap()?;
            f_out.write_all(&buf_out)?;
        }
    }
    
    Ok(())
}


/// Handles file encryption operations using dual-layer encryption.
///
/// Combines ChaCha20-Poly1305 and AES-256-GCM-SIV for encryption.
struct Encryption;

impl Encryption {
    /// Hashes a user-provided password and an optional user-provided key file using Argon2.
    ///
    /// Generates a random salt and derives a cryptographic key from the password and, if available, 
    /// the key file using the Argon2id password hashing algorithm.
    ///
    /// # Arguments
    /// - `keyfilepath`: Optional path to an additional key file
    /// 
    /// # Returns
    /// - `Ok((pw_salt, key))` containing the salt and derived key
    /// - `Err` if password hashing or getting password/key file fails
    fn hash_password(keyfilepath: Option<&PathBuf>) -> Result<([u8; PW_SALT_SIZE], SecretSlice<u8>)> {
        // create random salt
        let mut pw_salt = [0u8; PW_SALT_SIZE];
        let mut rng = ChaCha20Rng::try_from_rng(&mut SysRng)?;
        rng.fill_bytes(&mut pw_salt);

        let pass = get_pass_bytes(keyfilepath, true)?;

        let mut key = SecretSlice::from(vec![0u8; KEY_SIZE]);
        Argon2::default().hash_password_into(pass.expose_secret(), &pw_salt, key.expose_secret_mut())
            .map_err(|e| format!("Failed to hash password: {:?}", e))?;

        Ok((pw_salt, key))
    }

    /// Encrypts a buffer using XChaCha20-Poly1305.
    ///
    /// Generates a random nonce and encrypts the buffer. The output includes
    /// the nonce prepended to the ciphertext for transmission.
    ///
    /// # Arguments
    /// - `key`: 32-byte encryption key
    /// - `buf`: Data to encrypt
    ///
    /// # Returns
    /// - `Ok(encrypted_data)` containing nonce + ciphertext + authentication tag
    /// - `Err` if initialization or encryption fails
    fn cha_encrypt_buffer(key: &SecretSlice<u8>, buf: &[u8]) -> Result<Vec<u8>> {
        let cipher = XChaCha20Poly1305::new_from_slice(key.expose_secret())
            .map_err(|e| format!("Failed to init encryption: {:?}", e))?;
        let nonce = XChaCha20Poly1305::generate_nonce(OsRng);
        let encrypted_buf = cipher.encrypt(&nonce, buf)
            .map_err(|e| format!("Failed to encrypt data: {:?}", e))?;
        let combined_data = [&nonce[..], &encrypted_buf[..]].concat();
        
        Ok(combined_data)
    }

    /// Encrypts a buffer using AES-256-GCM-SIV with HKDF key derivation.
    ///
    /// Derives a unique encryption key from the master key using HKDF-SHA256 with random info bytes,
    /// then encrypts using AES-256-GCM-SIV. Output includes info + nonce + ciphertext + tag.
    ///
    /// # Arguments
    /// - `key`: 32-byte master key
    /// - `buf`: Data to encrypt
    ///
    /// # Returns
    /// - `Ok(encrypted_data)` containing info + nonce + ciphertext + authentication tag
    /// - `Err` if key derivation or encryption fails
    fn aes_encrypt_buffer(key: &SecretSlice<u8>, buf: &[u8]) -> Result<Vec<u8>> {
        // key derivation
        let mut info = [0u8; HKDF_INFO_SIZE];
        OsRng.fill_bytes(&mut info);
        // derive a different random key for each encryption
        let okm = key_derivation(key, &info)?;

        let cipher = Aes256GcmSiv::new_from_slice(okm.expose_secret())
            .map_err(|e| format!("Failed to init encryption: {:?}", e))?;
        let nonce =  Aes256GcmSiv::generate_nonce(OsRng);
        let encrypted_buf = cipher.encrypt(&nonce, buf)
            .map_err(|e| format!("Failed to encrypt data: {:?}", e))?;
        let combined_data = [&info[..], &nonce[..], &encrypted_buf[..]].concat();
        
        Ok(combined_data)
    }

    /// Encrypts a file using dual-layer encryption (ChaCha20 + AES-256-GCM-SIV).
    ///
    /// Prompts user for password, derives encryption key using Argon2, and encrypts
    /// the file in chunks across multiple threads. Output file gets `.cce` extension.
    ///
    /// # Arguments
    /// - `filepath_in`: Path to input file to encrypt
    /// - `keyfilepath`: Optional path to an additional key file
    ///
    /// # Returns
    /// - `Ok(())` on successful encryption
    /// - `Err` if file operations, password handling, or encryption fails
    fn encrypt(filepath_in: &PathBuf, keyfilepath: Option<&PathBuf>) -> Result<()> {
        let mut filepath_out = filepath_in.clone();
        filepath_out.add_extension(ENCRYPTED_FILE_EXT);
    
        let f_in  = File::open(filepath_in)?;
        let mut f_out = File::create(filepath_out)?;

        let (pw_salt, key) = Self::hash_password(keyfilepath)?;

        // write password salt to file at first
        f_out.write_all(&pw_salt)?;

        crypt_io(f_in, f_out, CHUNK_SIZE, &key, 
            Self::cha_encrypt_buffer, 
            Self::aes_encrypt_buffer
        )?;

        Ok(())
    }
}


/// Handles file decryption operations using dual-layer decryption.
///
/// Reverses ChaCha20-Poly1305 and AES-256-GCM-SIV encryption applied during encryption.
struct Decryption;

impl Decryption {
    /// Hashes a user-provided password using Argon2 with supplied salt and optional key file.
    ///
    /// Derives a cryptographic key from the password using the provided salt, the optional key file,
    /// and Argon2id algorithm, allowing recovery of the original key used for encryption.
    ///
    /// # Arguments
    /// - `pw_salt`: Salt bytes to use for hashing
    /// - `keyfilepath`: Optional path to an additional key file
    ///
    /// # Returns
    /// - `Ok(key)` containing the derived key
    /// - `Err` if password hashing or getting password/key file fails
    fn hash_password(pw_salt: &[u8], keyfilepath: Option<&PathBuf>) -> Result<SecretSlice<u8>> {
        let pass = get_pass_bytes(keyfilepath, false)?;

        let mut key = SecretSlice::from(vec![0u8; KEY_SIZE]);
        Argon2::default().hash_password_into(pass.expose_secret(), pw_salt, key.expose_secret_mut())
            .map_err(|e| format!("Failed to hash password: {:?}", e))?;

        Ok(key)
    }

    /// Decrypts a buffer encrypted with XChaCha20-Poly1305.
    ///
    /// Extracts the nonce from the beginning of the buffer and decrypts the remainder
    /// using the provided key. Verifies authentication tag during decryption.
    ///
    /// # Arguments
    /// - `key`: 32-byte decryption key
    /// - `buf`: Data containing nonce + ciphertext + authentication tag
    ///
    /// # Returns
    /// - `Ok(plaintext)` containing decrypted data
    /// - `Err` if decryption fails or authentication tag verification fails
    fn cha_decrypt_buffer(key: &SecretSlice<u8>, buf: &[u8]) -> Result<Vec<u8>> {
        let cipher = XChaCha20Poly1305::new_from_slice(key.expose_secret())
            .map_err(|e| format!("Failed to init decryption: {:?}", e))?;
        let nonce = XNonce::from_slice(&buf[..CHA_NONCE_SIZE]);
        let decrypted_buf = cipher.decrypt(nonce, &buf[CHA_NONCE_SIZE..])
            .map_err(|e| format!("Failed to decrypt data: {:?}", e))?; 

        Ok(decrypted_buf)
    }

    /// Decrypts a buffer encrypted with AES-256-GCM-SIV using HKDF key derivation.
    ///
    /// Extracts info and nonce from the buffer, derives the session key using HKDF-SHA256,
    /// and decrypts using AES-256-GCM-SIV. Verifies authentication tag during decryption.
    ///
    /// # Arguments
    /// - `key`: 32-byte master key
    /// - `buf`: Data containing info + nonce + ciphertext + authentication tag
    ///
    /// # Returns
    /// - `Ok(plaintext)` containing decrypted data
    /// - `Err` if key derivation fails or decryption/authentication fails
    fn aes_decrypt_buffer(key: &SecretSlice<u8>, buf: &[u8]) -> Result<Vec<u8>> {
        let info = &buf[..HKDF_INFO_SIZE];
        let nonce = &buf[HKDF_INFO_SIZE..(HKDF_INFO_SIZE + AES_NONCE_SIZE)]; 
        let encrypted_data= &buf[(HKDF_INFO_SIZE + AES_NONCE_SIZE)..]; 

        let okm = key_derivation(key, info)?;

        let cipher = Aes256GcmSiv::new_from_slice(okm.expose_secret())
            .map_err(|e| format!("Failed to init decryption: {:?}", e))?;
        let nonce = Nonce::from_slice(nonce);
        let decrypted_buf = cipher.decrypt(nonce, encrypted_data)
            .map_err(|e| format!("Failed to decrypt data: {:?}", e))?; 

        Ok(decrypted_buf)
    }

    /// Decrypts a file encrypted with dual-layer encryption (AES-256-GCM-SIV + ChaCha20).
    ///
    /// Reads salt from file, prompts user for password, derives encryption key using Argon2,
    /// and decrypts the file in chunks across multiple threads. Output file has `.cce` suffix removed.
    ///
    /// # Arguments
    /// - `filepath_in`: Path to encrypted input file (must end with `.cce`)
    /// - `keyfilepath`: Optional path to an additional key file
    ///
    /// # Returns
    /// - `Ok(())` on successful decryption
    /// - `Err` if file operations, password handling, or decryption fails
    fn decrypt(filepath_in: &PathBuf, keyfilepath: Option<&PathBuf>) -> Result<()> {
        let mut filepath_out = filepath_in.clone();
        if filepath_in.extension() == Some(std::ffi::OsStr::new(ENCRYPTED_FILE_EXT)) {
            // remove encrypted-file-extension
            filepath_out.set_extension("");
        } else {
            return Err(format!("Invalid filename, it does not end with .{ENCRYPTED_FILE_EXT}").into())
        }

        let mut f_in  = File::open(filepath_in)?;
        let f_out = File::create(filepath_out)?;

        let mut pw_salt = [0u8; PW_SALT_SIZE];
        f_in.read_exact(&mut pw_salt)?;

        let key = Self::hash_password(&pw_salt, keyfilepath)?;

        crypt_io(
            f_in, 
            f_out, 
            CHUNK_SIZE + HKDF_INFO_SIZE + AES_NONCE_SIZE + AES_TAG_SIZE + CHA_NONCE_SIZE + CHA_TAG_SIZE, 
            &key,
            Self::aes_decrypt_buffer, 
            Self::cha_decrypt_buffer
        )?;

        Ok(())
    }
}


// ======================================================================
// Unit tests
// ======================================================================

#[cfg(test)]
mod tests {
    use super::*;

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
        std::fs::write(&filepath_kf, data_kf).unwrap();

        // repeated read should return the same hash which should not be all zeros
        let hash1 = read_and_hash_keyfile(&filepath_kf).unwrap();
        let hash2 = read_and_hash_keyfile(&filepath_kf).unwrap();
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, [0u8; 64]);

        // empty file
        let data_kf = [];
        std::fs::write(&filepath_kf, data_kf).unwrap();
        let hash1 = read_and_hash_keyfile(&filepath_kf).unwrap();
        let hash2 = read_and_hash_keyfile(&filepath_kf).unwrap();
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, [0u8; 64]);

        // big file
        let data_kf = vec![0xa5; MAX_KEYFILE_CHUNKS * CHUNK_SIZE];
        std::fs::write(&filepath_kf, data_kf).unwrap();
        let hash1 = read_and_hash_keyfile(&filepath_kf).unwrap();
        let hash2 = read_and_hash_keyfile(&filepath_kf).unwrap();
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, [0u8; 64]);

        // more than chunk size
        let mut data_kf = vec![0; CHUNK_SIZE + 10];
        rand::rng().fill_bytes(&mut data_kf);
        std::fs::write(&filepath_kf, data_kf).unwrap();
        let hash1 = read_and_hash_keyfile(&filepath_kf).unwrap();
        let hash2 = read_and_hash_keyfile(&filepath_kf).unwrap();
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, [0u8; 64]);

        // key file does not exist
        assert!(read_and_hash_keyfile(&PathBuf::from("test_miss")).is_err());

        // cleanup
        let _ = std::fs::remove_file(&filepath_kf);
    }

    #[test]
    fn test_get_pass_bytes() {
        // no key file
        let pass = get_pass_bytes(None, false).unwrap();
        assert_eq!("abc123test".as_bytes(), pass.expose_secret());

        // with key file
        let filepath_kf = PathBuf::from("test_gpb.bin");
        let data_kf = [0xa5; 50];
        std::fs::write(&filepath_kf, data_kf).unwrap();
        let pass = get_pass_bytes(Some(&filepath_kf), false).unwrap();
        assert!(pass.expose_secret().starts_with("abc123test".as_bytes()));
        assert_eq!(pass.expose_secret().len(), "abc123test".len() + 64);

        // key file does not exist
        assert!(get_pass_bytes(Some(&PathBuf::from("test_miss")), false).is_err());

        // cleanup
        let _ = std::fs::remove_file(&filepath_kf);
    }

    #[test]
    fn test_key_derivation() {
        let mut key = vec![0u8; KEY_SIZE];
        rand::rng().fill_bytes(&mut key);
        let info = [0xa; HKDF_INFO_SIZE];
        let key_sec = SecretSlice::from(key.clone());

        // output shouldn't change if called again
        let okm1 = key_derivation(&key_sec, &info).unwrap();
        let okm2 = key_derivation(&key_sec, &info).unwrap();
        assert_eq!(okm1.expose_secret(), okm2.expose_secret());
        assert_eq!(okm1.expose_secret().len(), KEY_SIZE);
        assert_ne!(okm1.expose_secret(), [0; KEY_SIZE]);
        assert_ne!(okm1.expose_secret(), key);

        // different output on different info input
        let info = [0xb; HKDF_INFO_SIZE];
        let okm3 = key_derivation(&key_sec, &info).unwrap();
        assert_ne!(okm1.expose_secret(), okm3.expose_secret());

        // different output on different key input
        let mut key4 = key.clone();
        key4[0] ^= 0x01;
        let okm4 = key_derivation(&SecretSlice::from(key4), &info).unwrap();
        assert_ne!(okm3.expose_secret(), okm4.expose_secret());
    }

    #[test]
    fn test_hash_password_encrypt() {
        // salt and key should differ for each call
        let (salt1, key1) = Encryption::hash_password(None).unwrap();
        let (salt2, key2) = Encryption::hash_password(None).unwrap();
        assert_ne!(salt1, salt2);
        assert_ne!(key1.expose_secret(), key2.expose_secret());
        // salt, key should not be all zeros
        assert_ne!(salt1, [0u8; PW_SALT_SIZE]);
        assert_ne!(key1.expose_secret(), [0u8; KEY_SIZE]);

        // key file does not exist
        assert!(Encryption::hash_password(Some(&PathBuf::from("test_miss"))).is_err());
    }

    #[test]
    fn test_hash_password_decrypt() {
        let salt = [1u8; PW_SALT_SIZE];
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
        std::fs::write(&filepath_kf, &data_kf).unwrap();
        
        let key3 = Decryption::hash_password(&salt, Some(&filepath_kf)).unwrap();
        assert_ne!(key1.expose_secret(), key3.expose_secret());

        // key file does not exist
        assert!(Decryption::hash_password(&salt, Some(&PathBuf::from("test_miss"))).is_err());

        // cleanup
        let _ = std::fs::remove_file(&filepath_kf);
    }

    #[test]
    fn test_chacha_crypt_buffer() {
        let key: [u8; 32]  = rand::random();
        let key = SecretSlice::from(key.to_vec());
        let data: [u8; 100] = rand::random();

        let encrypt_data = Encryption::cha_encrypt_buffer(&key, &data).unwrap();
        let decrypt_data = Decryption::cha_decrypt_buffer(&key, &encrypt_data).unwrap();
        assert_eq!(encrypt_data.len(), data.len() + CHA_NONCE_SIZE + CHA_TAG_SIZE);
        assert_eq!(data, decrypt_data[..]);

        // second encryption must produce different output of the same input
        let encrypt_data2 = Encryption::cha_encrypt_buffer(&key, &data).unwrap();
        // nonce part must be different
        assert_ne!(encrypt_data[..CHA_NONCE_SIZE], encrypt_data2[..CHA_NONCE_SIZE]);
        // encrypted data part must be different
        assert_ne!(encrypt_data[CHA_NONCE_SIZE..], encrypt_data2[CHA_NONCE_SIZE..]);

        // corrupt 'nonce'
        let mut bad_data = encrypt_data.clone();
        bad_data[0] ^= 0xFF;
        assert!(Decryption::cha_decrypt_buffer(&key, &bad_data).is_err());

        // corrupt 'data'
        let mut bad_data = encrypt_data.clone();
        bad_data[CHA_NONCE_SIZE+1] ^= 0xFF;
        assert!(Decryption::cha_decrypt_buffer(&key, &bad_data).is_err());

        // wrong key
        let mut bad_key = key.clone();
        bad_key.expose_secret_mut()[0] ^= 0xFF;
        assert!(Decryption::cha_decrypt_buffer(&bad_key, &encrypt_data).is_err());
    }

    #[test]
    fn test_aes_crypt_buffer() {
        let key: [u8; 32]  = rand::random();
        let key = SecretSlice::from(key.to_vec());
        let data: [u8; 100] = rand::random();

        let encrypt_data = Encryption::aes_encrypt_buffer(&key, &data).unwrap();
        let decrypt_data = Decryption::aes_decrypt_buffer(&key, &encrypt_data).unwrap();
        assert_eq!(encrypt_data.len(), data.len() + HKDF_INFO_SIZE + AES_NONCE_SIZE + AES_TAG_SIZE);
        assert_eq!(data, decrypt_data[..]);

        // second encryption must produce different output of the same input
        let encrypt_data2 = Encryption::aes_encrypt_buffer(&key, &data).unwrap();
        // nonce part must be different
        assert_ne!(encrypt_data[..AES_NONCE_SIZE], encrypt_data2[..AES_NONCE_SIZE]);
        // encrypted data part must be different
        assert_ne!(encrypt_data[AES_NONCE_SIZE..], encrypt_data2[AES_NONCE_SIZE..]);

        // corrupt 'info'
        let mut bad_data = encrypt_data.clone();
        bad_data[0] ^= 0xFF;
        assert!(Decryption::aes_decrypt_buffer(&key, &bad_data).is_err());

        // corrupt 'nonce'
        let mut bad_data = encrypt_data.clone();
        bad_data[HKDF_INFO_SIZE+1] ^= 0xFF;
        assert!(Decryption::aes_decrypt_buffer(&key, &bad_data).is_err());

        // corrupt 'data'
        let mut bad_data = encrypt_data.clone();
        bad_data[AES_NONCE_SIZE+1] ^= 0xFF;
        assert!(Decryption::aes_decrypt_buffer(&key, &bad_data).is_err());

        // wrong key
        let mut bad_key = key.clone();
        bad_key.expose_secret_mut()[0] ^= 0xFF;
        assert!(Decryption::aes_decrypt_buffer(&bad_key, &encrypt_data).is_err());
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
        std::fs::write(&filepath_in, &data).unwrap();

        assert_eq!(get_password_from_user(false).unwrap().expose_secret(), "abc123test");

        // encrypt, backup original file, decrypt
        Encryption::encrypt(&filepath_in, None).unwrap();
        // encrypted file must be different than original data
        assert_ne!(data, std::fs::read(&filepath_out).unwrap());
        // backup by renaming
        std::fs::rename(&filepath_in, &filepath_org).unwrap();
        Decryption::decrypt(&filepath_out, None).unwrap();

        // read and compare decrypted file against backup
        let decrypt_data = std::fs::read(&filepath_in).unwrap();
        assert_eq!(data, decrypt_data[..]);

        // cleanup
        let _ = std::fs::remove_file(&filepath_in);
        let _ = std::fs::remove_file(&filepath_out);
        let _ = std::fs::remove_file(&filepath_org);
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
        std::fs::write(&filepath_in, &data).unwrap();

        let mut data_kf = vec![0; 1024 * 1024 * 2];
        rand::rng().fill_bytes(&mut data_kf);
        std::fs::write(&filepath_kf, &data_kf).unwrap();

        // use keyfile, encrypt, backup original file, decrypt
        Encryption::encrypt(&filepath_in, Some(&filepath_kf)).unwrap();
        std::fs::rename(&filepath_in, &filepath_org).unwrap();
        Decryption::decrypt(&filepath_out, Some(&filepath_kf)).unwrap();

        // read and compare decrypted file against backup
        let decrypt_data = std::fs::read(&filepath_in).unwrap();
        assert_eq!(data, decrypt_data[..]);

        // key file does not exist
        assert!(Encryption::encrypt(&filepath_in, Some(&PathBuf::from("test_miss"))).is_err());
        assert!(Decryption::decrypt(&filepath_out, Some(&PathBuf::from("test_miss"))).is_err());

        // input file does not exist
        assert!(Encryption::encrypt(&PathBuf::from("test_miss"), None).is_err());
        assert!(Decryption::decrypt(&PathBuf::from("test_miss"), None).is_err());

        // cleanup
        let _ = std::fs::remove_file(&filepath_in);
        let _ = std::fs::remove_file(&filepath_out);
        let _ = std::fs::remove_file(&filepath_org);
        let _ = std::fs::remove_file(&filepath_kf);
    }

    #[test]
    #[ignore="only for benchmarking"]
    fn test_crypt_bench() {
        // a file 'ttt' must already exist
        let filepath_in = PathBuf::from("ttt");     
        let mut filepath_out = filepath_in.clone();
        filepath_out.add_extension(ENCRYPTED_FILE_EXT);

        Encryption::encrypt(&filepath_in, None).unwrap();
        Decryption::decrypt(&filepath_out, None).unwrap();
    }

}