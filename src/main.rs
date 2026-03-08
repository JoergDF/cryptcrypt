use std::fs::File;
use std::io::{Read, Write};
use std::error::Error;
use argon2::Argon2;
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::{Rng, SeedableRng};
use rand::rngs::SysRng;
use rand_chacha::ChaCha20Rng;
use aes_gcm_siv::{
    aead::{rand_core::RngCore, Aead, KeyInit, OsRng}, 
    Aes256GcmSiv, AeadCore, Nonce
};
use zeroize::{Zeroize, Zeroizing};
use typenum::Unsigned;
use clap::Parser;
use rpassword::prompt_password;
use hkdf::Hkdf;
use sha2::Sha256;
use std::thread;


const ENCRYPTED_FILE_EXT: &str = ".cce";
const CHUNK_SIZE:     usize = 1024 * 1024;
const PW_SALT_SIZE:   usize = 32; 
const KEY_SIZE:       usize = 32; 
const AES_NONCE_SIZE: usize = <Aes256GcmSiv as AeadCore>::NonceSize::USIZE; 
const AES_TAG_SIZE:   usize = <Aes256GcmSiv as AeadCore>::TagSize::USIZE;
const CHA_NONCE_SIZE: usize = <XChaCha20Poly1305 as AeadCore>::NonceSize::USIZE; 
const CHA_TAG_SIZE:   usize = <XChaCha20Poly1305 as AeadCore>::TagSize::USIZE;
const HKDF_INFO_SIZE: usize = 12; 


/// Program for encryption and decryption of a file. 
/// If no option is given, file is encrypted.
#[derive(Parser)]
#[command(version, about, verbatim_doc_comment, long_about = None)]
struct Args {
    /// Decrypt file
    #[arg(short, long, default_value_t = false)]
    decrypt: bool,

    /// File that should be encrypted or decrypted
    file: String,
}

/// Main entry point for the cryptcrypt application.
///
/// Parses command-line arguments and dispatches to either encryption or decryption
/// based on the provided flags.
///
/// # Returns
/// - `Ok(())` on successful completion
/// - `Err` if an error occurs during encryption/decryption
fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let filename_in = args.file;

    if args.decrypt {
       Decryption.decrypt(filename_in)?;
    } else {
       Encryption.encrypt(filename_in)?;
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
fn get_password_from_user(verify: bool) -> Result<String, Box<dyn Error>> {
    if cfg!(test) {
        println!("!!! Test-password used !!!");
        return Ok("abc123test".to_string())
    }

    let mut password = prompt_password("Enter password: ")?;
    
    if verify {
        let mut password_rep = prompt_password("Repeat password: ")?;

        if password != password_rep {
            password.zeroize();
            password_rep.zeroize();
            return Err("Passwords do not match!".into());
        }
        password_rep.zeroize();
    }

    Ok(password)
}


/// Derives output key material (OKM) using HKDF-SHA256.
///
/// HKDF (HMAC-based Key Derivation Function) expands a pseudo-random key (PRK)
/// into a derived key of specified length using provided info bytes.
///
/// # Arguments
/// - `key`: The pseudo-random key (PRK) for HKDF. Caller must ensure high entropy.
/// - `info`: Information bytes for HKDF expand phase.
/// - `okm`: Mutable output buffer to fill with derived key material.
///
/// # Returns
/// - `Ok(())` on successful key derivation
/// - `Err` if PRK length is invalid or requested output length is invalid
fn key_derivation(key: &[u8], info: &[u8], okm: &mut [u8]) -> Result<(), Box<dyn Error>> {
    let hk = Hkdf::<Sha256>::from_prk(key)
        .map_err(|e| format!("Invalid PRK length for HKDF: {:?}", e))?;
    hk.expand(info, okm)
        .map_err(|e| format!("Invalid length for HKDF expand: {:?}", e))?;
    Ok(())
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
fn crypt_io(mut f_in: File, mut f_out: File, chunk_size: usize, key: Zeroizing<[u8; 32]>, 
    crypt_fn1: fn(&[u8], &[u8]) -> Result<Vec<u8>, Box<dyn Error>>,
    crypt_fn2: fn(&[u8], &[u8]) -> Result<Vec<u8>, Box<dyn Error>>) 
    -> Result<(), Box<dyn Error>> 
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
                    let buf_tmp = crypt_fn1(key.as_ref(), &buf_in[..count_in])
                        .map_err(|e| e.to_string())?;
                    let buf_out = crypt_fn2(key.as_ref(), &buf_tmp)
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
/// Combines ChaCha20-Poly1305 and AES-256-GCM-SIV for defense-in-depth encryption.
struct Encryption;

impl Encryption {
    /// Hashes a user-provided password using Argon2.
    ///
    /// Generates a random salt and derives a cryptographic key from the password
    /// using the Argon2id password hashing algorithm.
    ///
    /// # Returns
    /// - `Ok((pw_salt, key))` containing the salt and derived key
    /// - `Err` if password hashing fails
    fn hash_password(&self) -> Result<([u8; PW_SALT_SIZE], [u8; KEY_SIZE]), Box<dyn Error>> {
        // create random salt
        let mut pw_salt = [0u8; PW_SALT_SIZE];
        let mut rng = ChaCha20Rng::try_from_rng(&mut SysRng)?;
        rng.fill_bytes(&mut pw_salt);

        let mut password = get_password_from_user(true)?;
        let mut key = Zeroizing::new([0u8; KEY_SIZE]);
        Argon2::default().hash_password_into(password.as_bytes(), &pw_salt, key.as_mut())
            .map_err(|e| format!("Failed to hash password: {:?}", e))?;

        password.zeroize();
        Ok((pw_salt, *key))
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
    fn cha_encrypt_buffer(key: &[u8], buf: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let cipher = XChaCha20Poly1305::new_from_slice(key)
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
    fn aes_encrypt_buffer(key: &[u8], buf: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        // key derivation
        let mut info = [0u8; HKDF_INFO_SIZE];
        let mut okm = Zeroizing::new([0u8; KEY_SIZE]); // output key material
        OsRng.fill_bytes(&mut info);
        // derive a different random key for each encryption
        key_derivation(key, &info, okm.as_mut())?;

        let cipher = Aes256GcmSiv::new_from_slice(okm.as_ref())
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
    /// - `filename_in`: Path to input file to encrypt
    ///
    /// # Returns
    /// - `Ok(())` on successful encryption
    /// - `Err` if file operations, password handling, or encryption fails
    fn encrypt(&self, filename_in: String) -> Result<(), Box<dyn Error>> {
        let filename_out = filename_in.clone() + ENCRYPTED_FILE_EXT;
    
        let f_in  = File::open(filename_in)?;
        let mut f_out = File::create(filename_out)?;

        let mut key = Zeroizing::new([0u8; KEY_SIZE]);
        let pw_salt;
        (pw_salt, *key) = self.hash_password()?;

        // write password salt to file at first
        f_out.write_all(&pw_salt)?;

        crypt_io(f_in, f_out, CHUNK_SIZE, key, Self::cha_encrypt_buffer, Self::aes_encrypt_buffer)?;

        Ok(())
    }
}


/// Handles file decryption operations using dual-layer decryption.
///
/// Reverses ChaCha20-Poly1305 and AES-256-GCM-SIV encryption applied during encryption.
struct Decryption;

impl Decryption {
    /// Hashes a user-provided password using Argon2 with supplied salt.
    ///
    /// Derives a cryptographic key from the password using the provided salt
    /// and Argon2id algorithm, allowing recovery of the original key used for encryption.
    ///
    /// # Arguments
    /// - `pw_salt`: Salt bytes to use for hashing
    ///
    /// # Returns
    /// - `Ok(key)` containing the derived key
    /// - `Err` if password hashing fails
    fn hash_password(&self, pw_salt: &[u8]) -> Result<[u8; KEY_SIZE], Box<dyn Error>> {
        let mut password = get_password_from_user(false)?;
        let mut key = Zeroizing::new([0u8; KEY_SIZE]);
        Argon2::default().hash_password_into(password.as_bytes(), pw_salt, key.as_mut())
            .map_err(|e| format!("Failed to hash password: {:?}", e))?;

        password.zeroize();
        Ok(*key)
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
    fn cha_decrypt_buffer(key: &[u8], buf: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let cipher = XChaCha20Poly1305::new_from_slice(key)
            .map_err(|e| format!("Failed to init encryption: {:?}", e))?;
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
    fn aes_decrypt_buffer(key: &[u8], buf: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let info = &buf[..HKDF_INFO_SIZE];
        let nonce = &buf[HKDF_INFO_SIZE..(HKDF_INFO_SIZE + AES_NONCE_SIZE)]; 
        let encrypted_data= &buf[(HKDF_INFO_SIZE + AES_NONCE_SIZE)..]; 

        let mut okm = Zeroizing::new([0u8; KEY_SIZE]); // output key material
        key_derivation(key, info, okm.as_mut())?;

        let cipher = Aes256GcmSiv::new_from_slice(okm.as_ref())
            .map_err(|e| format!("Failed to init encryption: {:?}", e))?;
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
    /// - `filename_in`: Path to encrypted input file (must end with `.cce`)
    ///
    /// # Returns
    /// - `Ok(())` on successful decryption
    /// - `Err` if file operations, password handling, or decryption fails
    fn decrypt(&self, filename_in: String) -> Result<(), Box<dyn Error>> {
        let mut filename_out = filename_in.clone();
        if filename_in.ends_with(ENCRYPTED_FILE_EXT) {
            filename_out.replace_range((filename_in.len() - ENCRYPTED_FILE_EXT.len()).., "");
        } else {
            return Err(format!("Invalid filename, it does not end with {ENCRYPTED_FILE_EXT}").into())
        }

        let mut f_in  = File::open(filename_in)?;
        let f_out = File::create(filename_out)?;

        let mut pw_salt = [0u8; PW_SALT_SIZE];
        f_in.read_exact(&mut pw_salt)?;
        let mut key = Zeroizing::new([0u8; KEY_SIZE]);
        *key = self.hash_password(&pw_salt)?;

        crypt_io(
            f_in, 
            f_out, 
            CHUNK_SIZE + HKDF_INFO_SIZE + AES_NONCE_SIZE + AES_TAG_SIZE + CHA_NONCE_SIZE + CHA_TAG_SIZE, 
            key,
            Self::aes_decrypt_buffer, 
            Self::cha_decrypt_buffer
        )?;

        Ok(())
    }
}


// Unit tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chacha_crypt_buffer() {
        let key: [u8; 32]  = rand::random();
        let data: [u8; 32] = rand::random();

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
        let mut bad_key = key;
        bad_key[0] ^= 0xFF;
        assert!(Decryption::cha_decrypt_buffer(&bad_key, &encrypt_data).is_err());
    }

    #[test]
    fn test_aes_crypt_buffer() {
        let key: [u8; 32]  = rand::random();
        let data: [u8; 32] = rand::random();

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
        let mut bad_key = key;
        bad_key[0] ^= 0xFF;
        assert!(Decryption::aes_decrypt_buffer(&bad_key, &encrypt_data).is_err());
    }

    #[test]
    fn test_crypt() {
        // create file with random data for encryption
        let filename = "test_cc.bin";
        let mut data = vec![0; 1024 * 3000];
        rand::rng().fill_bytes(&mut data);
        std::fs::write(filename, &data).unwrap();

        assert_eq!(get_password_from_user(false).unwrap(), "abc123test");

        // encrypt, backup original file, decrypt
        Encryption.encrypt(filename.to_string()).unwrap();
        std::fs::rename(filename, filename.to_string() + ".org").unwrap();
        Decryption.decrypt(filename.to_string() + ENCRYPTED_FILE_EXT).unwrap();

        // read and compare decrypted file against backup
        let decrypt_data = std::fs::read(filename).unwrap();
        assert_eq!(data, decrypt_data[..]);

        // cleanup
        let _ = std::fs::remove_file(filename);
        let _ = std::fs::remove_file(filename.to_string() + ENCRYPTED_FILE_EXT);
        let _ = std::fs::remove_file(filename.to_string() + ".org");
    }

    #[test]
    #[ignore]
    fn test_crypt_bench() {
        let filename = "ttt";         

        Encryption.encrypt(filename.to_string()).unwrap();
        Decryption.decrypt(filename.to_string() + ENCRYPTED_FILE_EXT).unwrap();
    }

}