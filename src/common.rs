use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use rpassword::prompt_password;
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
    let password = SecretString::from(
        if cfg!(test) {
            println!("!!! Test-password used !!!");
            "abc123test".to_string()
        } else {
            prompt_password("Enter password: ")?
        }
    );

    if verify {
        let password_rep = SecretString::from( 
            if cfg!(test) {
                "abc123test".to_string()
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
}