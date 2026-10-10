#![no_main]

use libfuzzer_sys::fuzz_target;
use cryptcrypt::encryption::Encryption;
use cryptcrypt::decryption::Decryption;
use chacha20poly1305::XChaCha20Poly1305;
use aes_gcm_siv::Aes256GcmSiv;
use aes_gcm_siv::KeyInit;

// fuzzing of compression, encryption, decryption of chunks
fuzz_target!(|data: &[u8]| {
    let key = [42u8; 32];
    let cipher_cha = XChaCha20Poly1305::new_from_slice(&key).unwrap();
    let cipher_aes = Aes256GcmSiv::new_from_slice(&key).unwrap();

    let chunk_count = data.get(0).copied().unwrap_or(0);
    let final_flag = (chunk_count & 0x01) != 0;
    let aad: &[u8] = if data.len() >= 33 {
        &data[1..33]
    } else {
        &[]
    };

    let mut enc_data = Encryption::compress_buffer(data).unwrap();
    Encryption::cha_encrypt_buffer(&cipher_cha, &mut enc_data, chunk_count.into(), final_flag, aad).unwrap();
    Encryption::aes_encrypt_buffer(&cipher_aes, &mut enc_data, chunk_count.into(), final_flag, aad).unwrap();

    Decryption::aes_decrypt_buffer(&cipher_aes, &mut enc_data, chunk_count.into(), final_flag, aad).unwrap();
    Decryption::cha_decrypt_buffer(&cipher_cha, &mut enc_data, chunk_count.into(), final_flag, aad).unwrap();
    let unzip_data = Decryption::decompress_buffer(&enc_data).unwrap();

    assert_eq!(data, unzip_data);
});
