#![no_main]

use libfuzzer_sys::arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use rand::Rng;
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
    file_sizes: Vec<u16>,
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
    let base_dir = PathBuf::from(DATA_PATH);

    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_nanos();
    let random: u32 = rand::rng().random();  
    let keypath = base_dir.join( PathBuf::from(format!("key{:x}{:x}", random, now)) ); 
    
    // write data to a file, hence it can be read by encryption
    // For file-/pathnames use a random number and nano seconds, required for multiple jobs
    let path_in;
    if arb_in.file_sizes.len() == 0 {
        return;
    } else if arb_in.file_sizes.len() == 1 {
        let mut data = vec![0; arb_in.file_sizes[0] as usize];
        rand::rng().fill_bytes(&mut data);
        path_in = base_dir.join( PathBuf::from(format!("dat{:x}{:x}", random, now)) ); 
        fs::write(&path_in, &data).unwrap();
    } else {
        path_in = base_dir.join( PathBuf::from(format!("dir{:x}{:x}", random, now)) ); 
        fs::create_dir(&path_in).unwrap();
        
        for (i, fsize) in arb_in.file_sizes.iter().enumerate() {
            let mut data = vec![0; *fsize as usize];
            rand::rng().fill_bytes(&mut data);
            let filepath_in = path_in.join( PathBuf::from(format!("dat{:x}{:x}{:x}", random, now, i)) );
            fs::write(&filepath_in, &data).unwrap();
        }
    }

     // add file extension of encrypted file depending on whether file should be split
    let mut filepath_out = path_in.clone();
    if arb_in.split.is_empty() {
        filepath_out.add_extension(ENCRYPTED_FILE_EXT); 
    } else {
        filepath_out.add_extension(SPLIT_ENC_FILE_EXT);
    }

    // if there are data for a keyfile, write it to a file, hence it can be read by encryption
    let mut filepath_key: Option<PathBuf> = None;
    if let Some(keydata) = arb_in.keydata {
        fs::write(&keypath, &keydata).unwrap();
        filepath_key = Some(keypath);
    }

    // encrypt data and decrypt its output 
    Encryption::encrypt(&path_in, None, filepath_key.as_ref(), arb_in.compress, arb_in.split, false).unwrap();

    let path_extract = base_dir.join( PathBuf::from(format!("out{:x}{:x}", random, now)) ); 
    Decryption::decrypt(&filepath_out, Some(&path_extract), filepath_key.as_ref(), false).unwrap();

    
    // clean up, delete files
    for file in glob(format!("{DATA_PATH}*{:x}{:x}*", random, now).as_str()).unwrap() {
        let _ = fs::remove_file(&file.unwrap());
    }
    let _ = fs::remove_dir_all(&path_in);
    let _ = fs::remove_dir_all(&path_extract);
});
