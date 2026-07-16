use std::path::{self, PathBuf};
use clap::Parser;
use std::process::ExitCode;
use parse_size::Config;
use cryptcrypt::encryption::Encryption;
use cryptcrypt::decryption::Decryption;
use cryptcrypt::Result;


#[derive(Parser)]
#[command(version, about, verbatim_doc_comment, long_about = None)]
/// Program for encryption and decryption of file or directory.
/// If no option is given, input is encrypted. A directory as input causes the build of an encrypted archive.
/// With option -s the encrypted output is split into files with extensions .c00, .c01, .c02, ...
/// If a file ending on .c00 is decrypted, the whole split series will be read.
struct Args {
    /// Output directory, it is created if it does not exist
    #[arg(short, long)]
    out_dir: Option<PathBuf>,

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

    /// File that should be encrypted or decrypted. 
    /// If a directory is given, its contents is archived and encrypted.
    file_or_directory: PathBuf,
}

/// Main entry point for the cryptcrypt application.
///
/// # Returns
/// - `ExitCode::SUCCESS` on successful completion
/// - `ExitCode::FAILURE` if an error occurs 
fn main() -> ExitCode {
    let result = run();

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {}", e);
            ExitCode::FAILURE
        }
    }
}

/// Run the code.
/// 
/// Parses command-line arguments and dispatches to either encryption or decryption
/// based on the provided flags.
fn run() -> Result<()> {
    let args = Args::parse();

    let filepath = args.file_or_directory.canonicalize()?;
    let keyfilepath = args.keyfile.map(|keyf| keyf.canonicalize()).transpose()?;
    let output_dir = args.out_dir.map(path::absolute).transpose()?;

    if args.decrypt {
        Decryption::decrypt(&filepath, output_dir.as_ref(), keyfilepath.as_ref())?;
    } else {
        Encryption::encrypt(&filepath, output_dir.as_ref(), keyfilepath.as_ref(), args.compress, args.split)?;
    }

    Ok(())
}
