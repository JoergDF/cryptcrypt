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
use aes_gcm_siv::{aead::{Aead, KeyInit, OsRng}, Aes256GcmSiv, AeadCore, Nonce};
use typenum::Unsigned;
use clap::Parser;
use rpassword::{prompt_password, read_password_from_bufread};
use std::io::Cursor;
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use sha3::Sha3_512;
use secrecy::{ExposeSecret, ExposeSecretMut, SecretSlice, SecretString};


const ENCRYPTED_FILE_EXT: &str  = "cce";
const CHUNK_SIZE: usize         = 1_048_576; // 1024 * 1024 bytes
const MAX_KEYFILE_CHUNKS: usize = 64;
const SALT_SIZE: usize          = 32; 
const KEY_SIZE: usize           = 32; 
const AES_NONCE_SIZE: usize     = <Aes256GcmSiv as AeadCore>::NonceSize::USIZE; // 12 bytes
const AES_TAG_SIZE: usize       = <Aes256GcmSiv as AeadCore>::TagSize::USIZE;   // 16 bytes
const CHA_NONCE_SIZE: usize     = <XChaCha20Poly1305 as AeadCore>::NonceSize::USIZE; // 24 bytes
const CHA_TAG_SIZE: usize       = <XChaCha20Poly1305 as AeadCore>::TagSize::USIZE;   // 16 bytes

type Result<T> = std::result::Result<T, Box<dyn Error>>;

/// Parameters for file I/O operations during cryptographic processing.
///
/// Reduces function signature complexity.
struct FileParams {
    /// Input file to read data from
    f_in: File, 
    /// Output file to write processed data to
    f_out: File,
    /// Total size in bytes of input data remaining to be read
    f_in_size: u64, 
    /// Size in bytes of each chunk to process per iteration
    chunk_size: usize,
}


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
/// - `key`: The pseudo-random key (PRK) for HKDF with length 32. 
/// - `salt`: Salt bytes
/// - `info`: Information bytes for HKDF expand phase.
///
/// # Returns
/// - `Ok(okm)` output key material
/// - `Err` if PRK length is invalid or requested output length is invalid
fn key_derivation(key: &SecretSlice<u8>, salt: &[u8], info: &[u8]) -> Result<SecretSlice<u8>> {
    let hk = Hkdf::<Sha256>::new(Some(salt), key.expose_secret());
    let mut okm = SecretSlice::from(vec![0u8; KEY_SIZE]);
    hk.expand(info, okm.expose_secret_mut())
        .map_err(|e| format!("Invalid length for HKDF expand: {:?}", e))?;
    Ok(okm)
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
fn crypt_io(
    fp: &mut FileParams,
    key1: &SecretSlice<u8>, 
    key2: &SecretSlice<u8>,
    crypt_fn1: fn(&SecretSlice<u8>, &[u8], u32, bool) -> Result<Vec<u8>>,
    crypt_fn2: fn(&SecretSlice<u8>, &[u8], u32, bool) -> Result<Vec<u8>>
) -> Result<()> 
{
    let cpu_count = num_cpus::get();
    let mut chunk_count: u32 = 0;
    let mut file_remaining = fp.f_in_size;    

    while file_remaining > 0 {
        let mut child_threads = Vec::with_capacity(cpu_count);

        for _ in 0..cpu_count {
            let key1 = key1.clone();
            let key2 = key2.clone();

            let (read_size, final_chunk) = if file_remaining <= fp.chunk_size as u64 {
                (file_remaining as usize, true)
            } else {
                (fp.chunk_size, false)
            };
            file_remaining -= read_size as u64;

            let mut buf_in = vec![0u8; read_size];
            fp.f_in.read_exact(&mut buf_in)?;

            child_threads.push(thread::spawn(move || {
                    let buf_tmp = crypt_fn1(&key1, &buf_in, chunk_count, final_chunk)
                        .map_err(|e| e.to_string())?;
                    let buf_out = crypt_fn2(&key2, &buf_tmp, chunk_count, final_chunk)
                        .map_err(|e| e.to_string())?;
                    Ok::<Vec<u8>, String>(buf_out)
                }));
            
            if file_remaining == 0 {
                break;
            } 
            chunk_count += 1;
        }

        for child in child_threads {
            let buf_out = child.join().unwrap()?;
            fp.f_out.write_all(&buf_out)?;
        }
    }
    
    Ok(())
}


/// Handles file encryption operations using dual-layer encryption.
///
/// Combines ChaCha20-Poly1305 and AES-256-GCM-SIV for encryption.
struct Encryption;

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
    fn cha_encrypt_buffer(key: &SecretSlice<u8>, buf: &[u8], chunk_count: u32, final_chunk: bool) -> Result<Vec<u8>> {
        let cipher = XChaCha20Poly1305::new_from_slice(key.expose_secret())
            .map_err(|e| format!("Failed to init encryption: {:?}", e))?;
        let mut nonce = XChaCha20Poly1305::generate_nonce(OsRng);
        let nonce_org = nonce;

        // change nonce by XOR of chunk count and final chunk flag
        // that prevents reordering or truncation of chunk sequence
        nonce[0] ^= final_chunk as u8;
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
    /// the nonce prepended to the ciphertext for transmission.
    ///
    /// The `chunk_count` and `final_chunk` parameters are accepted for API
    /// compatibility with the ChaCha path but are ignored by this implementation.
    ///
    /// # Arguments
    /// - `key`: 32‑byte AES key stored in a `SecretSlice<u8>`
    /// - `buf`: Data to encrypt
    /// - `_chunk_count` — zero-based chunk index (ignored).
    /// - `_final_chunk` — `true` if this is the last chunk (ignored).
    ///
    /// # Returns
    /// - `Ok(encrypted_data)` containing nonce + ciphertext (+ authentication tag)
    /// - `Err` if key derivation or encryption fails
    fn aes_encrypt_buffer(key: &SecretSlice<u8>, buf: &[u8], _chunk_count: u32, _final_chunk: bool) -> Result<Vec<u8>> {
        let cipher = Aes256GcmSiv::new_from_slice(key.expose_secret())
            .map_err(|e| format!("Failed to init encryption: {:?}", e))?;
        let nonce =  Aes256GcmSiv::generate_nonce(OsRng);
        let encrypted_buf = cipher.encrypt(&nonce, buf)
            .map_err(|e| format!("Failed to encrypt data: {:?}", e))?;
        let combined_data = [&nonce[..], &encrypted_buf[..]].concat();
        
        Ok(combined_data)
    }

    /// Encrypts a file using dual-layer encryption (ChaCha20 + AES-256-GCM-SIV).
    ///
    /// Prompts user for password, derives master key using Argon2, derives keys for 
    /// ChaCha20 and AES-256-GCM-SIV, encrypts the file in chunks across multiple threads. 
    /// Output file gets `.cce` extension.
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

        let (salt_pw, key) = Self::hash_password(keyfilepath)?;
        let (salt_cha, key_cha, salt_aes, key_aes) = Self::derive_keys(&key)?;

        // write salts for password, chacha and aes key derivation to beginning of output file 
        f_out.write_all(&salt_pw)?;
        f_out.write_all(&salt_cha)?;
        f_out.write_all(&salt_aes)?;

        // set file parameters
        let f_in_size = f_in.metadata()?.len();
        let mut fp = FileParams {
            f_in, 
            f_out, 
            f_in_size, 
            chunk_size: CHUNK_SIZE,
        };

        crypt_io(
            &mut fp,
            &key_cha,
            &key_aes,
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
    fn cha_decrypt_buffer(key: &SecretSlice<u8>, buf: &[u8], chunk_count: u32, final_chunk: bool) -> Result<Vec<u8>> {
        let cipher = XChaCha20Poly1305::new_from_slice(key.expose_secret())
            .map_err(|e| format!("Failed to init decryption: {:?}", e))?;
        let mut nonce = *XNonce::from_slice(&buf[..CHA_NONCE_SIZE]);
        
        // change nonce by XOR of final chunk flag and chunk count
        nonce[0] ^= final_chunk as u8;
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
    /// The `chunk_count` and `final_chunk` parameters are accepted for API
    /// compatibility with the ChaCha path but are ignored by this implementation.
    ///
    /// # Arguments
    /// - `key`: 32‑byte AES key stored in a `SecretSlice<u8>`
    /// - `buf`: Data containing nonce + ciphertext (+ authentication tag)
    /// - `_chunk_count` — zero-based chunk index (ignored).
    /// - `_final_chunk` — `true` if this is the last chunk (ignored).
    ///
    /// # Returns
    /// - `Ok(plaintext)` containing decrypted data
    /// - `Err` if decryption fails or authentication tag verification fails
    fn aes_decrypt_buffer(key: &SecretSlice<u8>, buf: &[u8], _chunk_count: u32, _final_chunk: bool) -> Result<Vec<u8>> {
        let cipher = Aes256GcmSiv::new_from_slice(key.expose_secret())
            .map_err(|e| format!("Failed to init decryption: {:?}", e))?;
        let nonce = Nonce::from_slice(&buf[..AES_NONCE_SIZE]);
        let decrypted_buf = cipher.decrypt(nonce, &buf[AES_NONCE_SIZE..])
            .map_err(|e| format!("Failed to decrypt data: {:?}", e))?; 

        Ok(decrypted_buf)
    }

    /// Decrypts a file encrypted with dual-layer encryption (AES-256-GCM-SIV + ChaCha20).
    ///
    /// Reads salts from file, prompts user for password, derives master key using Argon2,
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

        let mut salt_pw = [0u8; SALT_SIZE];
        let mut salt_cha = [0u8; SALT_SIZE];
        let mut salt_aes = [0u8; SALT_SIZE];
        f_in.read_exact(&mut salt_pw)?;
        f_in.read_exact(&mut salt_cha)?;
        f_in.read_exact(&mut salt_aes)?;

        let key = Self::hash_password(&salt_pw, keyfilepath)?;
        let (key_cha, key_aes) = Self::derive_keys(&salt_cha, &salt_aes, &key)?;

        // set file parameters
        let f_in_size = f_in.metadata()?.len() - 3 * SALT_SIZE as u64;
        let mut fp = FileParams {
            f_in, 
            f_out, 
            f_in_size, 
            chunk_size: CHUNK_SIZE + AES_NONCE_SIZE + AES_TAG_SIZE + CHA_NONCE_SIZE + CHA_TAG_SIZE, 
        };

        crypt_io(
            &mut fp,
            &key_aes,
            &key_cha,
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
    use std::fs;

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

        let encrypt_data = Encryption::aes_encrypt_buffer(&key, &data, 0, false).unwrap();
        let decrypt_data = Decryption::aes_decrypt_buffer(&key, &encrypt_data, 0, false).unwrap();
        assert_eq!(encrypt_data.len(), data.len() + AES_NONCE_SIZE + AES_TAG_SIZE);
        assert_eq!(data, decrypt_data[..]);

        // second encryption must produce different output of the same input
        let encrypt_data2 = Encryption::aes_encrypt_buffer(&key, &data, 0, false).unwrap();
        // nonce part must be different
        assert_ne!(encrypt_data[..AES_NONCE_SIZE], encrypt_data2[..AES_NONCE_SIZE]);
        // encrypted data part must be different
        assert_ne!(encrypt_data[AES_NONCE_SIZE..], encrypt_data2[AES_NONCE_SIZE..]);

        // corrupt 'nonce'
        let mut bad_data = encrypt_data.clone();
        bad_data[0] ^= 0xFF;
        assert!(Decryption::aes_decrypt_buffer(&key, &bad_data, 0, false).is_err());

        // corrupt 'data'
        let mut bad_data = encrypt_data.clone();
        bad_data[AES_NONCE_SIZE+1] ^= 0xFF;
        assert!(Decryption::aes_decrypt_buffer(&key, &bad_data, 0, false).is_err());

        // wrong key
        let mut bad_key = key.clone();
        bad_key.expose_secret_mut()[0] ^= 0xFF;
        assert!(Decryption::aes_decrypt_buffer(&bad_key, &encrypt_data, 0, false).is_err());
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
        Encryption::encrypt(&filepath_in, None).unwrap();
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
        Encryption::encrypt(&filepath_in, Some(&filepath_kf)).unwrap();
        fs::rename(&filepath_in, &filepath_org).unwrap();
        Decryption::decrypt(&filepath_out, Some(&filepath_kf)).unwrap();

        // read and compare decrypted file against backup
        let decrypt_data = fs::read(&filepath_in).unwrap();
        assert_eq!(data, decrypt_data[..]);

        // decrypt without key file
        assert!(Decryption::decrypt(&filepath_out, None).is_err());

        // key file does not exist
        assert!(Encryption::encrypt(&filepath_in, Some(&PathBuf::from("test_miss"))).is_err());
        assert!(Decryption::decrypt(&filepath_out, Some(&PathBuf::from("test_miss"))).is_err());

        // input file does not exist
        assert!(Encryption::encrypt(&PathBuf::from("test_miss"), None).is_err());
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

        Encryption::encrypt(&filepath_in, None).unwrap();
        Decryption::decrypt(&filepath_out, None).unwrap();
    }

}