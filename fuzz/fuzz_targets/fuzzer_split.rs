#![no_main]

use libfuzzer_sys::fuzz_target;
use std::path::PathBuf;
use std::fs;
use rand::RngExt;
use std::time::SystemTime;
use glob::glob;
use cryptcrypt::common_io;
use cryptcrypt::SPLIT_ENC_FILE_EXT;


// directory for temporary input/output files (could be a RAM disk)
const DATA_PATH: &str = "/Volumes/RAMDisk1GB/";

// fuzzing of split algorithm (without encryption, decryption, compression)
//
// input data it written to split files which are then read
fuzz_target!(|input: (&[u8], Vec<u16>)| {
    let (data, split) = input;
    
    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_nanos();
    let random: u32 = rand::rng().random();
    let mut filepath = PathBuf::from(format!("{DATA_PATH}dat{:x}{:x}", random, now));     
    filepath.add_extension(SPLIT_ENC_FILE_EXT);

    // write data into split files
    let split_u64: Vec<u64> = split.iter().map(|x| {*x as u64}).collect();
    let mut wr = common_io::WriteOutput::new(filepath.clone(), split_u64).unwrap();
    wr.write_files(&[0]).unwrap(); // header
    wr.write_files(&data).unwrap();

    // read split files
    let mut rd = common_io::ReadInput::new(filepath, 100, 1).unwrap();
    // header
    let mut hdr = [1u8];
    rd.read_files(&mut hdr).unwrap();
    assert_eq!(hdr, [0]);
    // data
    let mut final_chunk = false;
    let mut data_out = vec![];
    while !final_chunk { 
        let dat;
        (dat, final_chunk) = rd.read_chunk().unwrap();
        data_out.extend(dat);
    }

    // input data and read data should be the same
    assert_eq!(data, data_out);

    // delete files
    for file in glob(format!("{DATA_PATH}*{:x}{:x}*", random, now).as_str()).unwrap() {
        let _ = fs::remove_file(&file.unwrap());
    }
});
