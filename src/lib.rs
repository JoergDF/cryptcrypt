use std::error::Error;
use typenum::Unsigned;
use aes_gcm_siv::{Aes256GcmSiv, AeadCore};
use chacha20poly1305::{XChaCha20Poly1305};


pub mod common;
pub mod common_io;
pub mod encryption;
pub mod decryption;
pub mod archive;


pub const FILE_FORMAT_VERSION: u8   = 5;
pub const ENCRYPTED_FILE_EXT: &str  = "cce";
pub const SPLIT_ENC_FILE_EXT: &str  = "c00";
pub const CHUNK_SIZE: usize         = 1_048_576;  // 1024 * 1024 bytes
pub const MAX_KEYFILE_CHUNKS: usize = 64;
pub const SALT_SIZE: usize          = 32; 
pub const KEY_SIZE: usize           = 32;
pub const COMPRESS_LENGTH_SIZE: usize = 3;
pub const AES_NONCE_SIZE: usize     = <Aes256GcmSiv as AeadCore>::NonceSize::USIZE;      // 12 bytes
pub const CHA_NONCE_SIZE: usize     = <XChaCha20Poly1305 as AeadCore>::NonceSize::USIZE; // 24 bytes
pub const AES_TAG_SIZE: usize       = <Aes256GcmSiv as AeadCore>::TagSize::USIZE;        // 16 bytes
pub const CHA_TAG_SIZE: usize       = <XChaCha20Poly1305 as AeadCore>::TagSize::USIZE;   // 16 bytes
pub const HEADER_SIZE: usize        = 3 * SALT_SIZE + 4 + CHA_NONCE_SIZE + CHA_TAG_SIZE + AES_NONCE_SIZE + AES_TAG_SIZE;

pub type Result<T> = std::result::Result<T, Box<dyn Error>>;
