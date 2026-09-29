use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use rpassword::prompt_password;
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use sha3::Sha3_512;
use secrecy::{ExposeSecret, ExposeSecretMut, SecretSlice, SecretString};
use zeroize::{Zeroize, Zeroizing};
use argon2::Argon2;
use chacha20poly1305::XChaCha20Poly1305;
use aes_gcm_siv::{Aes256GcmSiv, aead::KeyInit};
use ctap_hid_fido2::{
    fidokey::{
        get_info::{InfoParam, InfoOption}, 
        CredentialExtension, MakeCredentialArgsBuilder, AssertionExtension, GetAssertionArgsBuilder
    }, 
    Cfg, FidoKeyHidFactory, verifier
};

use crate::{Result, CHUNK_SIZE, MAX_KEYFILE_CHUNKS, KEY_SIZE, SALT_SIZE};

/// Creates file encryption/decryption ciphers.
#[derive(Default)]
pub struct KeyBuilder {
    /// Whether the password should be entered twice for confirmation.
    verify_password: bool,
    /// Password retained between header and body cipher creation.
    password: SecretString,
    /// FIDO2 credential ID used to request the authenticator's hmac-secret.
    pub credential_id_fido: Option<Vec<u8>>,
}

impl KeyBuilder {
    pub fn new(verify_password: bool) -> Self {
        let it = Self::default();
        Self { verify_password, ..it }
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
        let password = SecretString::from(
            if cfg!(test) || cfg!(fuzzing) {
                if !cfg!(fuzzing) { println!("!!! Test-password used !!!"); }
                "abc123test".to_string()
            } else {
                prompt_password("Enter password: ")?
            }
        );

        if verify {
            let password_rep = SecretString::from( 
                if cfg!(test) || cfg!(fuzzing) {
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

    /// Prompts the user to enter a PIN for the USB security key from the terminal.
    /// 
    /// # Returns
    /// - `Ok(pin)` containing the pin
    /// - `Err` if there is an I/O error
    fn get_fido_pin_from_user() -> Result<SecretString> {
        let pin = SecretString::from(
            prompt_password("Enter PIN of USB security key: ")?
        );
        Ok(pin)
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

    /// Retrieves an hmac-secret from the connected FIDO2 authenticator.
    ///
    /// Requires exactly one authenticator with the hmac-secret extension,
    /// enforced user verification, and a PIN. If no credential ID is stored,
    /// retrieves a credential ID from authenticator and saves it 
    /// in `self.credential_id_fido`.
    ///
    /// # Arguments
    /// - `salt`: Salt supplied to the authenticator's hmac-secret extension
    ///
    /// # Returns
    /// - `Ok(secret)` containing the authenticator's hmac-secret
    /// - `Err` if the authenticator is missing or unsupported, PIN input or
    ///   device interaction fails, or the credential response is invalid
    fn usb_fido2_hmac_secret(&mut self, salt: &[u8])-> Result<SecretSlice<u8>> {
        let rp_id = "cryptcrypt.cce";
        
        let devs = ctap_hid_fido2::get_fidokey_devices();
        if devs.is_empty() {
            return Err("FIDO authenticator missing".into());
        } else if devs.len() > 1 {
            return Err("Exactly one FIDO authenticator supported, disconnect all but one.".into());
        }

        let device = FidoKeyHidFactory::create_by_params(
            &[devs[0].param.clone()],
            &Cfg::init(),
        )?;

        if !device.enable_info_param(&InfoParam::ExtensionsHmacSecret)? {
            return Err("FIDO authenticator does not support the hmac-secret extension".into());
        }

        if Some(true) != device.enable_info_option(&InfoOption::AlwaysUv)? {
            return Err("User verification on FIDO authenticator not enforced".into());   
        }

        let mut pin = 
        if Some(true) == device.enable_info_option(&InfoOption::ClientPin)? {
            Self::get_fido_pin_from_user()?
        } else {
            return Err("PIN on FIDO authenticator not enabled".into())
        };

        let mut credential_public_key = None;
        if self.credential_id_fido.is_none() {
            // get credential ID
            println!("Registering USB security key...");

            let challenge = verifier::create_challenge();
            let ext = CredentialExtension::HmacSecret(Some(true));
            let make_credential_args = MakeCredentialArgsBuilder::new(rp_id, &challenge)
                .pin(pin.expose_secret())
                .extensions(&[ext])
                .build();
            let attestation = device.make_credential_with_args(&make_credential_args)?;
            
            let find = attestation
                .extensions
                .iter()
                .find(|&it| matches!(it, CredentialExtension::HmacSecret(Some(true))));
            if find.is_none() {
                return Err("FIDO authenticator connection error".into());
            }
            
            let verify_result = verifier::verify_attestation(rp_id, &challenge, &attestation);
            if !verify_result.is_success {
                return Err("FIDO authenticator connection error".into());
            }

            self.credential_id_fido = Some(verify_result.credential_id);
            credential_public_key = Some(verify_result.credential_public_key);
        }

        println!("Requesting data from USB security key...");

        // get hmac secret
        let challenge = verifier::create_challenge();
        let ext = AssertionExtension::HmacSecret(Some(salt.try_into()?));

        let get_assertion_args = GetAssertionArgsBuilder::new(rp_id, &challenge)
            .pin(pin.expose_secret())
            .credential_id(self.credential_id_fido.as_ref().unwrap())
            .extensions(&[ext])
            .build();
        let assertions = device.get_assertion_with_args(&get_assertion_args)?;
        pin.zeroize();

        let assertion = assertions
            .first()
            .ok_or("FIDO authenticator connection error")?;

        let find = assertion
            .extensions
            .iter()
            .find(|it| matches!(it, AssertionExtension::HmacSecret(_)));
        let hmac_secret =
        if let Some(AssertionExtension::HmacSecret(Some(hmac_sec))) = find {
            SecretSlice::from(Vec::from(hmac_sec))
        } else {
            return Err("FIDO authenticator connection error".into())
        };
        
        if let Some(cred_pub_key) = credential_public_key 
        && !verifier::verify_assertion(rp_id, &cred_pub_key, &challenge, assertion) {
            return Err("FIDO authenticator connection error".into());
        }
        
        println!("USB security key end");

        Ok(hmac_secret)
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

    /// Creates the encryption ciphers used for the file header.
    ///
    /// Prompts for the password, derives a key with Argon2 using `salt_pw`,
    /// then derives separate XChaCha20-Poly1305 and AES-256-GCM-SIV keys
    /// with HKDF-SHA256 using `salt_enc`.
    ///
    /// # Arguments
    /// - `salt_pw`: Salt used for Argon2 password hashing
    /// - `salt_enc`: Salt used for HKDF key derivation
    ///
    /// # Returns
    /// - `Ok((cipher_cha, cipher_aes))` containing the header encryption ciphers
    /// - `Err` if password input, password hashing, key derivation, or cipher
    ///   initialization fails
    pub fn get_password_and_create_header_ciphers(&mut self, salt_pw: &[u8], salt_enc: &[u8]) -> Result<(XChaCha20Poly1305, Aes256GcmSiv)> {
        self.password = Self::get_password_from_user(self.verify_password)?;

        let mut key = SecretSlice::from(vec![0u8; KEY_SIZE]);
        Argon2::default().hash_password_into(self.password.expose_secret().as_bytes(), salt_pw, key.expose_secret_mut())
            .map_err(|_e| "Failed to hash password")?;

        let key_cha = Self::key_derivation(&key, salt_enc, "header-xchacha20poly1305".as_bytes())?;
        let key_aes = Self::key_derivation(&key, salt_enc, "-header-aes-256-gcm-siv-".as_bytes())?;
        key.zeroize();

        let cipher_cha = XChaCha20Poly1305::new_from_slice(key_cha.expose_secret())?;
        let cipher_aes = Aes256GcmSiv::new_from_slice(key_aes.expose_secret())?;

        Ok((cipher_cha, cipher_aes))
    }

    /// Creates the encryption ciphers used for the file body.
    ///
    /// Combines the password with any supplied key-file hash and FIDO2
    /// hmac-secret, derives a key with Argon2 using `salt_pw`, then derives
    /// separate XChaCha20-Poly1305 and AES-256-GCM-SIV keys with HKDF-SHA256
    /// using `salt_enc`.
    ///
    /// # Arguments
    /// - `salt_pw`: Salt used for Argon2 password hashing
    /// - `salt_enc`: Salt used for HKDF key derivation
    /// - `keyfilepath`: Optional path to a key file; its hash is used
    ///   as an additional key input
    /// - `salt_fido`: Optional salt used to request an hmac-secret from the
    ///   FIDO2 authenticator
    ///
    /// # Returns
    /// - `Ok((cipher_cha, cipher_aes))` containing the body encryption ciphers
    /// - `Err` if key-file access, FIDO2 interaction, password hashing, key
    ///   derivation, or cipher initialization fails
    pub fn create_body_ciphers(&mut self, salt_pw: &[u8], salt_enc: &[u8], keyfilepath: Option<&PathBuf>, salt_fido: Option<&[u8]>) -> Result<(XChaCha20Poly1305, Aes256GcmSiv)> {
        let mut pwd = Zeroizing::new(Vec::with_capacity(self.password.expose_secret().len() + 64 + SALT_SIZE));
        
        if let Some(path) = keyfilepath {
            pwd.extend(
                Self::read_and_hash_keyfile(path)?
            );
        }
        
        if let Some(salt) = salt_fido {
            pwd.extend(
                self.usb_fido2_hmac_secret(salt)?.expose_secret()
            );
        }
        
        pwd.extend(self.password.expose_secret().as_bytes());

        let mut key = SecretSlice::from(vec![0u8; KEY_SIZE]);
        Argon2::default().hash_password_into(&pwd, salt_pw, key.expose_secret_mut())
            .map_err(|_e| "Failed to hash password")?;
        pwd.zeroize();
        self.password.zeroize();

        let key_cha = Self::key_derivation(&key, salt_enc, "body-xchacha20poly1305".as_bytes())?;
        let key_aes = Self::key_derivation(&key, salt_enc, "-body-aes-256-gcm-siv-".as_bytes())?;
        key.zeroize();
        
        let cipher_cha = XChaCha20Poly1305::new_from_slice(key_cha.expose_secret())?;
        let cipher_aes = Aes256GcmSiv::new_from_slice(key_aes.expose_secret())?;

        Ok((cipher_cha, cipher_aes))
    }
}


// ======================================================================
// Unit tests
// ======================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use aes_gcm_siv::aead::Aead;
use rand::Rng;
    use crate::{AES_NONCE_SIZE, CHA_NONCE_SIZE, SALT_SIZE};

    #[test]
    fn test_get_password_from_user() {
        let pw = KeyBuilder::get_password_from_user(false).unwrap();
        assert_eq!("abc123test", pw.expose_secret());

        let pw = KeyBuilder::get_password_from_user(true).unwrap();
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
        let hash1 = KeyBuilder::read_and_hash_keyfile(&filepath_kf).unwrap();
        let hash2 = KeyBuilder::read_and_hash_keyfile(&filepath_kf).unwrap();
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, [0u8; 64]);

        // empty file
        let data_kf = [];
        fs::write(&filepath_kf, data_kf).unwrap();
        let hash1 = KeyBuilder::read_and_hash_keyfile(&filepath_kf).unwrap();
        let hash2 = KeyBuilder::read_and_hash_keyfile(&filepath_kf).unwrap();
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, [0u8; 64]);

        // big file
        let data_kf = vec![0xa5; MAX_KEYFILE_CHUNKS * CHUNK_SIZE];
        fs::write(&filepath_kf, data_kf).unwrap();
        let hash1 = KeyBuilder::read_and_hash_keyfile(&filepath_kf).unwrap();
        let hash2 = KeyBuilder::read_and_hash_keyfile(&filepath_kf).unwrap();
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, [0u8; 64]);

        // more than chunk size
        let mut data_kf = vec![0; CHUNK_SIZE + 10];
        rand::rng().fill_bytes(&mut data_kf);
        fs::write(&filepath_kf, data_kf).unwrap();
        let hash1 = KeyBuilder::read_and_hash_keyfile(&filepath_kf).unwrap();
        let hash2 = KeyBuilder::read_and_hash_keyfile(&filepath_kf).unwrap();
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, [0u8; 64]);

        // key file does not exist
        assert!(KeyBuilder::read_and_hash_keyfile(&PathBuf::from("test_miss")).is_err());

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
        let okm1 = KeyBuilder::key_derivation(&key_sec, &salt, &info).unwrap();
        let okm2 = KeyBuilder::key_derivation(&key_sec, &salt, &info).unwrap();
        assert_eq!(okm1.expose_secret(), okm2.expose_secret());
        assert_eq!(okm1.expose_secret().len(), KEY_SIZE);
        assert_ne!(okm1.expose_secret(), [0; KEY_SIZE]);
        assert_ne!(okm1.expose_secret(), key);

        // different output on different info input
        let info = [0xb; 12];
        let okm3 = KeyBuilder::key_derivation(&key_sec, &salt, &info).unwrap();
        assert_ne!(okm1.expose_secret(), okm3.expose_secret());

        // different output on different info input
        let mut salt4 = salt;
        salt4[0] ^= 0xFF;
        let okm4 = KeyBuilder::key_derivation(&key_sec, &salt4, &info).unwrap();
        assert_ne!(okm3.expose_secret(), okm4.expose_secret());

        // different output on different key input
        let mut key4 = key;
        key4[0] ^= 0x01;
        let okm5 = KeyBuilder::key_derivation(&SecretSlice::from(key4.to_vec()), &salt4, &info).unwrap();
        assert_ne!(okm4.expose_secret(), okm5.expose_secret());

        // Even empty salt, should produce a valid non-zero key
        let salt6= [];
        let okm6 = KeyBuilder::key_derivation(&key_sec, &salt6, &info).unwrap();
        assert_ne!(okm6.expose_secret(), [0u8; KEY_SIZE]);
        assert_ne!(okm1.expose_secret(), okm6.expose_secret());
    }

    #[test]
    fn test_get_password_and_create_header_ciphers() {
        let salt_pw = [1u8; SALT_SIZE];
        let salt_enc = [2u8; SALT_SIZE];

        let mut kb = KeyBuilder::new(false);
        let (cipher_cha, cipher_aes) = kb
            .get_password_and_create_header_ciphers(&salt_pw, &salt_enc).unwrap();
        assert_eq!(kb.password.expose_secret(), "abc123test");

        // both ciphers must be able to encrypt/decrypt a message
        let nonce_cha = [0u8; CHA_NONCE_SIZE];
        let nonce_aes = [0u8; AES_NONCE_SIZE];
        let plaintext = b"header-data";

        let ct_cha = cipher_cha.encrypt(&nonce_cha.into(), plaintext.as_ref()).unwrap();
        let pt_cha = cipher_cha.decrypt(&nonce_cha.into(), ct_cha.as_ref()).unwrap();
        assert_eq!(pt_cha, plaintext);

        let ct_aes = cipher_aes.encrypt(&nonce_aes.into(), plaintext.as_ref()).unwrap();
        let pt_aes = cipher_aes.decrypt(&nonce_aes.into(), ct_aes.as_ref()).unwrap();
        assert_eq!(pt_aes, plaintext);

        // changing the salt changes the derived key / ciphertext
        let mut kb2 = KeyBuilder::new(false);
        let (cipher_cha2, cipher_aes2) = kb2
            .get_password_and_create_header_ciphers(&[9u8; SALT_SIZE], &salt_enc) .unwrap();

        let ct_cha2 = cipher_cha2.encrypt(&nonce_cha.into(), plaintext.as_ref()).unwrap();
        let ct_aes2 = cipher_aes2.encrypt(&nonce_aes.into(), plaintext.as_ref()).unwrap();
        assert_ne!(ct_cha, ct_cha2);
        assert_ne!(ct_aes, ct_aes2);
    }

    #[test]
    fn test_create_body_ciphers() {
        let salt_pw  = [1u8; SALT_SIZE];
        let salt_enc = [2u8; SALT_SIZE];

        let mut kb = KeyBuilder::new(false);
        let _ = kb.get_password_and_create_header_ciphers(&salt_pw, &salt_enc).unwrap();

        let (cipher_cha, cipher_aes) = kb
            .create_body_ciphers(&salt_pw, &salt_enc, None, None).unwrap();

         // both ciphers must be able to encrypt/decrypt a message
        let nonce_cha = [0u8; CHA_NONCE_SIZE];
        let nonce_aes = [0u8; AES_NONCE_SIZE];
        let plaintext = b"body-data";

        let ct_cha = cipher_cha.encrypt(&nonce_cha.into(), plaintext.as_ref()).unwrap();
        let pt_cha = cipher_cha.decrypt(&nonce_cha.into(), ct_cha.as_ref()).unwrap();
        assert_eq!(pt_cha, plaintext);

        let ct_aes = cipher_aes.encrypt(&nonce_aes.into(), plaintext.as_ref()).unwrap();
        let pt_aes = cipher_aes.decrypt(&nonce_aes.into(), ct_aes.as_ref()).unwrap();
        assert_eq!(pt_aes, plaintext);

        // changing the salt changes the derived key / ciphertext
        let mut kb2 = KeyBuilder::new(false);
        let _ = kb2.get_password_and_create_header_ciphers(&[9u8; SALT_SIZE], &salt_enc) .unwrap();
        let (cipher_cha2, cipher_aes2) = kb2
            .create_body_ciphers(&[9u8; SALT_SIZE], &salt_enc, None, None).unwrap();    

        let ct_cha2 = cipher_cha2.encrypt(&nonce_cha.into(), plaintext.as_ref()).unwrap();
        let ct_aes2 = cipher_aes2.encrypt(&nonce_aes.into(), plaintext.as_ref()).unwrap();
        assert_ne!(ct_cha, ct_cha2);
        assert_ne!(ct_aes, ct_aes2);

        // with keyfile
        let keyfile = PathBuf::from("test_hdr_body_keyfile.bin");
        fs::write(&keyfile, vec![0xA5; 128]).unwrap();

        let mut kb = KeyBuilder::new(false);
        let _ = kb.get_password_and_create_header_ciphers(&salt_pw, &salt_enc).unwrap();
        let (cipher_cha3, cipher_aes3) = kb
            .create_body_ciphers(&salt_pw, &salt_enc, Some(&keyfile), None).unwrap();

        let ct_cha3 = cipher_cha3.encrypt(&nonce_cha.into(), plaintext.as_ref()).unwrap();
        let pt_cha = cipher_cha3.decrypt(&nonce_cha.into(), ct_cha3.as_ref()).unwrap();
        assert_eq!(pt_cha, plaintext);

        let ct_aes3 = cipher_aes3.encrypt(&nonce_aes.into(), plaintext.as_ref()).unwrap();
        let pt_aes = cipher_aes3.decrypt(&nonce_aes.into(), ct_aes3.as_ref()).unwrap();
        assert_eq!(pt_aes, plaintext);

        // ciphertexts should change with keyfile
        assert_ne!(ct_cha, ct_cha3);
        assert_ne!(ct_aes, ct_aes3);
        
        let _ = fs::remove_file(&keyfile);
    }
}