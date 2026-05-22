#![no_main]

use libfuzzer_sys::fuzz_target;
use secrecy::SecretSlice;
use cryptcrypt::encryption::Encryption;
use cryptcrypt::decryption::Decryption;


// fuzzing of compression, encryption, decryption of chunks
fuzz_target!(|data: &[u8]| {
    let key = [42u8; 32];
    let key = SecretSlice::from(key.to_vec());

    let chunk_count = data.get(0).copied().unwrap_or(0);
    let final_flag = (chunk_count & 0x01) != 0;

    let zip_data = Encryption::compress_buffer(data).unwrap();
    let cha_enc = Encryption::cha_encrypt_buffer(&key, &zip_data, chunk_count.into(), final_flag).unwrap();
    let aes_enc = Encryption::aes_encrypt_buffer(&key, &cha_enc).unwrap();

    let aes_dec = Decryption::aes_decrypt_buffer(&key, &aes_enc).unwrap();
    let cha_dec = Decryption::cha_decrypt_buffer(&key, &aes_dec, chunk_count.into(), final_flag).unwrap();
    let unzip_data = Decryption::decompress_buffer(&cha_dec).unwrap();

    assert_eq!(data, unzip_data);
});
