#![no_main]

use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use rand::RngExt;
use std::path::PathBuf;
use std::fs;
use std::time::SystemTime;
use glob::glob;
use cryptcrypt::encryption::Encryption;
use cryptcrypt::decryption::Decryption;
use cryptcrypt::ENCRYPTED_FILE_EXT;
use cryptcrypt::SPLIT_ENC_FILE_EXT;


#[derive(Arbitrary, Clone, Debug)]
struct FuzzInput {
    data: Vec<u8>,
    keydata: Option<Vec<u8>>,
    compress: bool,
    split: Vec<u64>,
}

// directory for temporary input/output files and keyfile (could be a RAM disk)
const DATA_PATH: &str = "/Volumes/RAMDisk1GB/";

// fuzzing of encryption and decryption (with optional compression)
//
// input data is written to files hence encryption can read it from there,
// output data is read from files which are written by decryption
fuzz_target!(|arb_in: FuzzInput| {
    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_nanos();
    let random: u32 = rand::rng().random();
    // For filenames use a random number and nano seconds, required for multiple jobs
    let filepath_in = PathBuf::from(format!("{DATA_PATH}dat{:x}{:x}", random, now));     
    let keypath = PathBuf::from(format!("{DATA_PATH}key{:x}{:x}", random, now)); 
    
    // add file extension of encrypted file depending on whether file should be split
    let mut filepath_out = filepath_in.clone();
    if arb_in.split.is_empty() {
        filepath_out.add_extension(ENCRYPTED_FILE_EXT); 
    } else {
        filepath_out.add_extension(SPLIT_ENC_FILE_EXT);
    }

    // write data to a file, hence it can be read by encryption
    fs::write(&filepath_in, &arb_in.data).unwrap();

    // if there are data for a keyfile, write it to a file, hence it can be read by encryption
    let mut filepath_key: Option<PathBuf> = None;
    if let Some(keydata) = arb_in.keydata {
        fs::write(&keypath, &keydata).unwrap();
        filepath_key = Some(keypath);
    }

    // encrypt data and decrypt its output 
    Encryption::encrypt(&filepath_in, filepath_key.as_ref(), arb_in.compress, arb_in.split).unwrap();
    Decryption::decrypt(&filepath_out, filepath_key.as_ref()).unwrap();

    // read decrypted output
    let data_out = fs::read(&filepath_in).unwrap();
    
    // input to encryption and output of decryption should be the same
    assert_eq!(arb_in.data, data_out);

    // delete files
    for file in glob(format!("{DATA_PATH}*{:x}{:x}*", random, now).as_str()).unwrap() {
        let _ = fs::remove_file(&file.unwrap());
    }
});
