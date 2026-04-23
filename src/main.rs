use std::error::Error;
use std::path::PathBuf;
use clap::Parser;
use std::process::ExitCode;
use typenum::Unsigned;
use aes_gcm_siv::{Aes256GcmSiv, AeadCore};
use chacha20poly1305::{XChaCha20Poly1305};
use parse_size::Config;
use crate::encryption::Encryption;
use crate::decryption::Decryption;


mod common;
mod common_io;
mod encryption;
mod decryption;


const FILE_FORMAT_VERSION: u8   = 3;
const ENCRYPTED_FILE_EXT: &str  = "cce";
const SPLIT_ENC_FILE_EXT: &str  = "c00";
const CHUNK_SIZE: usize         = 1_048_576;  // 1024 * 1024 bytes
const MAX_KEYFILE_CHUNKS: usize = 64;
const SALT_SIZE: usize          = 32; 
const KEY_SIZE: usize           = 32;
const AES_LENGTH_SIZE: usize    = 3;
const HEADER_SIZE: usize        = 2 + 3 * SALT_SIZE;
const AES_NONCE_SIZE: usize     = <Aes256GcmSiv as AeadCore>::NonceSize::USIZE;      // 12 bytes
const CHA_NONCE_SIZE: usize     = <XChaCha20Poly1305 as AeadCore>::NonceSize::USIZE; // 24 bytes
#[cfg(test)]
const AES_TAG_SIZE: usize       = <Aes256GcmSiv as AeadCore>::TagSize::USIZE;        // 16 bytes
#[cfg(test)]
const CHA_TAG_SIZE: usize       = <XChaCha20Poly1305 as AeadCore>::TagSize::USIZE;   // 16 bytes


type Result<T> = std::result::Result<T, Box<dyn Error>>;


#[derive(Parser)]
#[command(version, about, verbatim_doc_comment, long_about = None)]
/// Program for encryption and decryption of a file.
/// If no option is given, file is encrypted. 
/// With option -s the encrypted output is split into files with extensions .c00, .c01, .c02, ...
/// If a file ending on .c00 is decrypted, the whole split series will be read.
struct Args {
    /// Decrypt file (with extension '.cce' or for split series '.c00')
    #[arg(short, long, default_value_t = false)]
    decrypt: bool,

    /// Additional key file to supplement the password
    #[arg(short, long)]
    keyfile: Option<PathBuf>,

    /// Compress data before encryption, automatically detected on decryption
    #[arg(short = 'z', long, default_value_t = false)]
    compress: bool,

    /// Split encrypted data into pieces of binary byte sizes (e.g. 2g,3g,1g) [G|g|M|m|K|k]
    #[arg(short, long, value_delimiter = ',', 
      value_parser = |s: &str| { let cfg = Config::new().with_binary(); cfg.parse_size(s) })]
    split: Vec<u64>,

    /// File that should be encrypted or decrypted
    file: PathBuf,
}

/// Main entry point for the cryptcrypt application.
///
/// Parses command-line arguments and dispatches to either encryption or decryption
/// based on the provided flags.
///
/// # Returns
/// - `ExitCode::SUCCESS` on successful completion
/// - `ExitCode::FAILURE` if an error occurs during encryption/decryption
/// 
fn main() -> ExitCode {
    let args = Args::parse();
    
    let filepath = args.file;
    let keyfilepath = args.keyfile;

    let result = 
        if args.decrypt {
            Decryption::decrypt(&filepath, keyfilepath.as_ref())
        } else {
            Encryption::encrypt(&filepath, keyfilepath.as_ref(), args.compress, args.split)
        };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{}", e);
            ExitCode::FAILURE
        }
    }
}
