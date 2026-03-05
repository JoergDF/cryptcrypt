use std::fs::File;
use std::io::{Read, Write};
use std::error::Error;
use aes_gcm_siv::Nonce;
use argon2::Argon2;
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::{Rng, SeedableRng};
use rand::rngs::SysRng;
use rand_chacha::ChaCha20Rng;
use aes_gcm_siv::{aead::{rand_core::RngCore, Aead, KeyInit, OsRng}, Aes256GcmSiv, AeadCore};
use zeroize::{Zeroize, Zeroizing};
use typenum::Unsigned;
use clap::Parser;
use rpassword::prompt_password;
use hkdf::Hkdf;
use sha2::Sha256;


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


fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    let filename_in = args.file;

    if !args.decrypt {
        Encryption.encrypt(filename_in)?;
    } else {
        Decryption.decrypt(filename_in)?;
    }

    Ok(())
}


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


/// Derive an OKM (output key material) using HKDF‑SHA256.
/// HKDF: Hashed Message Authentication Code (HMAC)-based key derivation function
///
/// Behavior:
/// - Treats `key` as the PRK (pseudo random key). This means the caller is
///   expected to provide a key that already has high entropy.
/// - Expands with the provided `info` into `okm` (the caller supplies the
///   output buffer and its desired length).
///
/// Arguments:
/// - `key`: PRK for HKDF.
/// - `info`: info bytes for HKDF expand.
/// - `okm`: mutable output buffer to fill with derived key material.
///
/// Returns:
/// - Ok(()) on success
/// - Err on invalid PRK length or requested output length.
fn key_derivation(key: &[u8], info: &[u8], okm: &mut [u8]) -> Result<(), Box<dyn Error>> {
    let hk = Hkdf::<Sha256>::from_prk(key)
        .map_err(|e| format!("Invalid PRK length for HKDF: {:?}", e))?;
    hk.expand(info, okm)
        .map_err(|e| format!("Invalid length for HKDF expand: {:?}", e))?;
    Ok(())
}

struct Encryption;

impl Encryption {
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

    fn cha_encrypt_buffer(&self, key: &[u8], buf: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let cipher = XChaCha20Poly1305::new_from_slice(key)
            .map_err(|e| format!("Failed to init encryption: {:?}", e))?;
        let nonce = XChaCha20Poly1305::generate_nonce(OsRng);
        let encrypted_buf = cipher.encrypt(&nonce, buf)
            .map_err(|e| format!("Failed to encrypt data: {:?}", e))?;
        let combined_data = [&nonce[..], &encrypted_buf[..]].concat();
        
        Ok(combined_data)
    }

    fn aes_encrypt_buffer(&self, key: &[u8], buf: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
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

    fn encrypt(&self, filename_in: String) -> Result<(), Box<dyn Error>> {
        let filename_out = filename_in.clone() + ENCRYPTED_FILE_EXT;
    
        let mut f_in  = File::open(filename_in)?;
        let mut f_out = File::create(filename_out)?;

        let mut key = Zeroizing::new([0u8; KEY_SIZE]);
        let pw_salt;
        (pw_salt, *key) = self.hash_password()?;

        // write password salt to file at first
        f_out.write_all(&pw_salt)?;

        // Read chunks from file
        let mut buf_in = vec![0u8; CHUNK_SIZE];
        
        // todo: use many threads
        loop {
            let count_in = f_in.read(&mut buf_in)?;
            if count_in == 0 { 
                break;
            }

            let buf_tmp = self.cha_encrypt_buffer(key.as_ref(), &buf_in[..count_in])?;
            let buf_out = self.aes_encrypt_buffer(key.as_ref(), &buf_tmp)?;

            f_out.write_all(&buf_out)?;
        }

        Ok(())
    }
}



struct Decryption;

impl Decryption {
    fn hash_password(&self, pw_salt: &[u8]) -> Result<[u8; KEY_SIZE], Box<dyn Error>> {
        let mut password = get_password_from_user(false)?;
        let mut key = Zeroizing::new([0u8; KEY_SIZE]);
        Argon2::default().hash_password_into(password.as_bytes(), pw_salt, key.as_mut())
            .map_err(|e| format!("Failed to hash password: {:?}", e))?;

        password.zeroize();
        Ok(*key)
    }

    fn cha_decrypt_buffer(&self, key: &[u8], buf: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let cipher = XChaCha20Poly1305::new_from_slice(key)
            .map_err(|e| format!("Failed to init encryption: {:?}", e))?;
        let nonce = XNonce::from_slice(&buf[..CHA_NONCE_SIZE]);
        let decrypted_buf = cipher.decrypt(nonce, &buf[CHA_NONCE_SIZE..])
            .map_err(|e| format!("Failed to decrypt data: {:?}", e))?; 

        Ok(decrypted_buf)
    }

    fn aes_decrypt_buffer(&self, key: &[u8], buf: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
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

    fn decrypt(&self, filename_in: String) -> Result<(), Box<dyn Error>> {
        let mut filename_out = filename_in.clone();
        if filename_in.ends_with(ENCRYPTED_FILE_EXT) {
            filename_out.replace_range((filename_in.len() - ENCRYPTED_FILE_EXT.len()).., "");
        } else {
            return Err(format!("Invalid filename, it does not end with {ENCRYPTED_FILE_EXT}").into())
        }

        let mut f_in  = File::open(filename_in)?;
        let mut f_out = File::create(filename_out)?;

        let mut pw_salt = [0u8; PW_SALT_SIZE];
        f_in.read_exact(&mut pw_salt)?;
        let mut key = Zeroizing::new([0u8; KEY_SIZE]);
        *key = self.hash_password(&pw_salt)?;

        // Read chunks from file
        let mut buf_in = vec![0u8; 
            CHUNK_SIZE + HKDF_INFO_SIZE + AES_NONCE_SIZE + AES_TAG_SIZE + CHA_NONCE_SIZE + CHA_TAG_SIZE];

        loop {
            let count_in = f_in.read(&mut buf_in)?;
            if count_in == 0 { 
                break;
            }

            let buf_tmp = self.aes_decrypt_buffer(key.as_ref(), &buf_in[..count_in])?;
            let buf_out = self.cha_decrypt_buffer(key.as_ref(), &buf_tmp)?;

            f_out.write_all(&buf_out)?;
        }

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

        let encrypt_data = Encryption.cha_encrypt_buffer(&key, &data).unwrap();
        let decrypt_data = Decryption.cha_decrypt_buffer(&key, &encrypt_data).unwrap();
        assert_eq!(encrypt_data.len(), data.len() + CHA_NONCE_SIZE + CHA_TAG_SIZE);
        assert_eq!(data, decrypt_data[..]);

        // second encryption must produce different output of the same input
        let encrypt_data2 = Encryption.cha_encrypt_buffer(&key, &data).unwrap();
        // nonce part must be different
        assert_ne!(encrypt_data[..CHA_NONCE_SIZE], encrypt_data2[..CHA_NONCE_SIZE]);
        // encrypted data part must be different
        assert_ne!(encrypt_data[CHA_NONCE_SIZE..], encrypt_data2[CHA_NONCE_SIZE..]);

        // corrupt 'nonce'
        let mut bad_data = encrypt_data.clone();
        bad_data[0] ^= 0xFF;
        assert!(Decryption.cha_decrypt_buffer(&key, &bad_data).is_err());

        // corrupt 'data'
        let mut bad_data = encrypt_data.clone();
        bad_data[CHA_NONCE_SIZE+1] ^= 0xFF;
        assert!(Decryption.cha_decrypt_buffer(&key, &bad_data).is_err());

        // wrong key
        let mut bad_key = key;
        bad_key[0] ^= 0xFF;
        assert!(Decryption.cha_decrypt_buffer(&bad_key, &encrypt_data).is_err());
    }

    #[test]
    fn test_aes_crypt_buffer() {
        let key: [u8; 32]  = rand::random();
        let data: [u8; 32] = rand::random();

        let encrypt_data = Encryption.aes_encrypt_buffer(&key, &data).unwrap();
        let decrypt_data = Decryption.aes_decrypt_buffer(&key, &encrypt_data).unwrap();
        assert_eq!(encrypt_data.len(), data.len() + HKDF_INFO_SIZE + AES_NONCE_SIZE + AES_TAG_SIZE);
        assert_eq!(data, decrypt_data[..]);

        // second encryption must produce different output of the same input
        let encrypt_data2 = Encryption.aes_encrypt_buffer(&key, &data).unwrap();
        // nonce part must be different
        assert_ne!(encrypt_data[..AES_NONCE_SIZE], encrypt_data2[..AES_NONCE_SIZE]);
        // encrypted data part must be different
        assert_ne!(encrypt_data[AES_NONCE_SIZE..], encrypt_data2[AES_NONCE_SIZE..]);

        // corrupt 'info'
        let mut bad_data = encrypt_data.clone();
        bad_data[0] ^= 0xFF;
        assert!(Decryption.aes_decrypt_buffer(&key, &bad_data).is_err());

        // corrupt 'nonce'
        let mut bad_data = encrypt_data.clone();
        bad_data[HKDF_INFO_SIZE+1] ^= 0xFF;
        assert!(Decryption.aes_decrypt_buffer(&key, &bad_data).is_err());

        // corrupt 'data'
        let mut bad_data = encrypt_data.clone();
        bad_data[AES_NONCE_SIZE+1] ^= 0xFF;
        assert!(Decryption.aes_decrypt_buffer(&key, &bad_data).is_err());

        // wrong key
        let mut bad_key = key;
        bad_key[0] ^= 0xFF;
        assert!(Decryption.aes_decrypt_buffer(&bad_key, &encrypt_data).is_err());
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
    fn test_crypt_bench1() {
        let filename = "ttt";         

        Encryption.encrypt(filename.to_string()).unwrap();
        Decryption.decrypt(filename.to_string() + ENCRYPTED_FILE_EXT).unwrap();
    }

    #[test]
    fn test_crypt_bench2() {
        let key: [u8; 32]  = rand::random();
        
        let mut buf_in = vec![0u8; 1024 * 1024];
        rand::rng().fill_bytes(&mut buf_in);
        
        for _ in 0..100 {
            let buf_tmp = Encryption.cha_encrypt_buffer(key.as_ref(), &buf_in[..]).unwrap();
            let buf_out = Encryption.aes_encrypt_buffer(key.as_ref(), &buf_tmp).unwrap();

            let buf_tmp2 = Decryption.aes_decrypt_buffer(key.as_ref(), &buf_out).unwrap();
            let _buf_out = Decryption.cha_decrypt_buffer(key.as_ref(), &buf_tmp2).unwrap();
        }
    }
}