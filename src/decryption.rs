use std::thread;
use std::io::Read;
use std::path::PathBuf;
use std::collections::HashMap;
use std::fs;
use std::env;
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use aes_gcm_siv::{Aes256GcmSiv, AeadInOut, Nonce};
use bzip2::read::BzDecoder;
use crossbeam_channel::{bounded, Sender, Receiver};

use crate::{Result, CHA_NONCE_SIZE, AES_NONCE_SIZE, CHUNK_SIZE, FILE_ID_SIZE, COMPRESS_LENGTH_SIZE, ENCRYPTED_FILE_EXT,
            SPLIT_ENC_FILE_EXT, CHA_TAG_SIZE, AES_TAG_SIZE, HEADER_SIZE, SALT_SIZE, FILE_FORMAT_VERSION};
use crate::common::KeyBuilder;
use crate::common_io::{CryptIo, CryptConfig, ReadInput, WriteFiles, WriteOutput};
use crate::archive::ArchiveWrite;
use crate::encryption::EncHeaderParams;


/// Handles file decryption operations using dual-layer decryption and decompression.
///
/// Reverses ChaCha20-Poly1305 and AES-256-GCM-SIV encryption applied during encryption.
pub struct Decryption;

impl Decryption {
    /// Decrypts a buffer encrypted with XChaCha20-Poly1305 using the per‑chunk nonce modification.
    ///
    /// Extracts the nonce from the end of the buffer and decrypts the remainder.
    /// Verifies authentication tag during decryption.
    /// The function reconstructs the modified nonce by XOR'ing:
    /// - `nonce[0]` with `final_chunk`, and
    /// - `nonce[1..]` with the little‑endian bytes of `chunk_count` (applied starting at index 1).
    ///
    /// The authenticated `associated_data` for a chunk is built from the file format
    /// version, a characterizing string, and a caller-provided array.
    /// This value must match the metadata used during encryption or authentication will fail.
    /// 
    /// # Arguments
    /// - `cipher`: XChaCha20-Poly1305 cipher struct initialized with key.
    /// - `buf_inout`: data-in: ciphertext (+ authentication tag) + nonce; data-out: decrypted data.
    /// - `chunk_count`: zero‑based chunk index; must match the value used during encryption.
    /// - `final_chunk`: `true` if this is the last chunk; must match the value used during encryption.
    /// - `more_associated_data`: Additional per-file metadata folded into the
    ///   authenticated `associated_data` for this chunk; must match the value used during encryption.
    /// 
    /// # Returns
    /// - `Ok()` on successful decryption
    /// - `Err` if decryption fails or authentication tag verification fails
    pub fn cha_decrypt_buffer(cipher: &XChaCha20Poly1305, buf_inout: &mut Vec<u8>, chunk_count: u32, final_chunk: bool, more_associated_data: &[u8]) -> Result<()> {
        let nonce_pos = buf_inout.len() - CHA_NONCE_SIZE;
        let mut nonce = XNonce::try_from(&buf_inout[nonce_pos..])?;
        
        // change nonce by XOR of final chunk flag and chunk count
        nonce[0] ^= u8::from(final_chunk);
        for (i, ccb) in chunk_count.to_le_bytes().iter().enumerate() {
            nonce[i+1] ^= ccb;
        }
        buf_inout.truncate(nonce_pos);

        let mut associated_data = vec![FILE_FORMAT_VERSION];
        associated_data.extend("Cha".as_bytes());
        associated_data.extend(more_associated_data);

        cipher.decrypt_in_place(&nonce, &associated_data, buf_inout)
            .map_err(|_e| "Failed to decrypt data!")?; // for better user info
        Ok(())
    }

    /// Decrypts a buffer encrypted with AES-256-GCM-SIV.
    ///
    /// Extracts the nonce from the end of the buffer and decrypts the remainder.
    /// Verifies authentication tag during decryption.
    ///
    /// The authenticated `associated_data` for an chunk is built from the file format
    /// version, characterizing string, and a caller-provided array, the little-endian bytes 
    /// of `chunk_count`, and the `final_chunk` flag. This value must match the metadata used 
    /// during encryption or authentication will fail.
    /// 
    /// # Arguments
    /// - `cipher`: Aes256GcmSiv cipher struct initialized with key
    /// - `buf_inout`: data-in: ciphertext (+ authentication tag) + nonce; data-out: decrypted data
    /// - `chunk_count`: zero‑based chunk index; must match the value used during encryption.
    /// - `final_chunk`: `true` if this is the last chunk; must match the value used during encryption.
    /// - `more_associated_data`: Additional per-file metadata folded into the
    ///   authenticated `associated_data` for this chunk; must match the value used during encryption.
    /// 
    /// # Returns
    /// - `Ok()` on successful decryption
    /// - `Err` if decryption fails or authentication tag verification fails
    pub fn aes_decrypt_buffer(cipher: &Aes256GcmSiv, buf_inout: &mut Vec<u8>, chunk_count: u32, final_chunk: bool, more_associated_data: &[u8]) -> Result<()> {
        let nonce_pos = buf_inout.len() - AES_NONCE_SIZE;
        let nonce = Nonce::try_from(&buf_inout[nonce_pos..])?;
        buf_inout.truncate(nonce_pos);

        let mut associated_data = vec![FILE_FORMAT_VERSION];
        associated_data.extend("Aes".as_bytes());
        associated_data.extend(more_associated_data);
        associated_data.extend(chunk_count.to_le_bytes());
        associated_data.push(u8::from(final_chunk));

        cipher.decrypt_in_place(&nonce, &associated_data, buf_inout)
            .map_err(|_e| "Failed to decrypt data!")?; // for better user info
        Ok(())
    }

    /// Decompresses a bzip2-compressed buffer.
    ///
    /// Reads the provided buffer with a bzip2 decoder and returns the
    /// decompressed result. This is the inverse of `Encryption::compress_buffer`.
    ///
    /// # Arguments
    /// - `buf`: compressed input bytes
    ///
    /// # Returns
    /// - `Ok(decompressed_bytes)` on success
    /// - `Err` if decompression or I/O fails
    pub fn decompress_buffer(buf: &[u8]) -> Result<Vec<u8>> {
        let mut decompressor = BzDecoder::new(buf);
        let mut decompressed_data = Vec::with_capacity(CHUNK_SIZE);
        decompressor.read_to_end(&mut decompressed_data)?;

        Ok(decompressed_data)
    }

    /// Re-segments a stream of decrypted fixed-sized fragments into length-prefixed compressed chunks.
    ///
    /// Reads decrypted fragment payloads from `rx_e` (items are `(Vec<u8>, chunk_index)`),
    /// reorders out-of-order fragments using a `HashMap`, concatenates payloads into an
    /// internal buffer and extracts complete compressed entries using the compact length
    /// prefix encoded in the first `COMPRESS_LENGTH_SIZE` bytes. Each extracted compressed
    /// entry is emitted to `tx_c` as `(Vec<u8>, new_chunk_count)`.
    ///
    /// # Arguments
    /// - `rx_e`: receiver of decrypted buffers `(Vec<u8>, chunk_count)` produced by earlier stages.
    /// - `tx_c`: sender for re-segmented compressed chunks `(Vec<u8>, new_chunk_count)`.
    ///
    /// # Returns
    /// - `Ok(())` on successful re-segmentation and sending of all output chunks.
    /// - `Err(...)` if a size conversion, IO, or channel send fails.
    pub fn resegment(rx_e: Receiver<(Vec<u8>, u32)>, tx_c: Sender<(Vec<u8>, u32)>) -> Result<()> {
        let mut pending_chunks = HashMap::new();
        let mut out_index = 0;
        let mut new_chunk_count: u32 = 0;
        let mut buf_out = Vec::with_capacity(CHUNK_SIZE * 2);
        let mut compressed_chunk_len: Option<usize> = None;

        for (buf_e, chunk_count) in rx_e {
            pending_chunks.insert(chunk_count, buf_e);

            while let Some(buf_in) = pending_chunks.remove(&out_index) {
                buf_out.extend(buf_in);
                out_index += 1;

                loop {
                    if let Some(c_chunk_len) = compressed_chunk_len {
                        // length bytes have been read, check if buffer contains enough bytes
                        if buf_out.len() >= c_chunk_len {
                            let new_chunk = buf_out.drain(..c_chunk_len).collect();
                            tx_c.send((new_chunk, new_chunk_count))?;

                            compressed_chunk_len = None;
                            new_chunk_count += 1;
                        } else {
                            break; // not enough data, get more
                        }
                    } else if buf_out.len() >= COMPRESS_LENGTH_SIZE {
                        // get length bytes at the start of a compressed chunk
                        let mut length_bytes: Vec<u8> = buf_out.drain(..COMPRESS_LENGTH_SIZE).collect();
                        length_bytes.push(0);
                        compressed_chunk_len = Some(
                            u32::from_le_bytes(
                                length_bytes.try_into().unwrap()
                            ).try_into()?
                        );
                    } else {
                        break; // not enough data, get more
                    }
                }
            }
        }
        
        if !buf_out.is_empty() {
            return Err("Decryption resegmentation end error".into());
        }

        Ok(())
    }
   
    /// Creates the multithreaded decryption pipeline and returns all worker handles.
    ///
    /// Incoming encrypted chunks are read from `rx_in` and processed in reverse order to
    /// the encryption pipeline. The function always starts decryption workers first. When
    /// compression is enabled, the decrypted inner payloads are reassembled,
    /// length-prefixed compressed fragments are extracted, and the recovered entries are
    /// decompressed before they are forwarded to `tx_out`.
    ///
    /// The exact behavior is:
    /// - allocate `cpu_count` decryption workers when compression is off,
    ///   or `max(1, cpu_count - c_thread_cnt)` workers when compression is on
    /// - each decryption worker reads `(Vec<u8>, u32, bool)` from `rx_in`, runs
    ///   AES-256-GCM-SIV and XChaCha20-Poly1305 decryption in sequence, and sends the
    ///   decrypted chunk as `(Vec<u8>, u32)` to either `tx_out` directly or to an internal
    ///   resegmentation channel if compression is active
    /// - when compression is enabled, a single resegmentation thread consumes the
    ///   decrypted chunks, concatenates them, reconstructs the length-prefixed compressed
    ///   entries, and sends each extracted payload as `(Vec<u8>, u32)` onward
    /// - decompression workers then call `decompress_buffer` and emit the final plaintext
    ///   chunks `(Vec<u8>, u32)` to `tx_out`
    ///
    /// # Arguments
    /// - `crypt_cfg`: Shared configuration containing the ciphers and the compression flag.
    /// - `rx_in`: Receiver of encrypted chunks as `(Vec<u8>, chunk_count, final_chunk)`.
    /// - `tx_out`: Sender for final plaintext chunks as `(Vec<u8>, chunk_count)`.
    /// - `cpu_count`: Number of logical CPU cores used to size the worker pool.
    ///
    /// # Returns
    /// - `Vec<thread::JoinHandle<Result<(), String>>>` containing the decryption,
    ///   resegmentation, and decompression worker handles.
    pub fn decrypt_pipe(
        crypt_cfg: &CryptConfig,
        rx_in: Receiver<(Vec<u8>, u32, bool)>, 
        tx_out: Sender<(Vec<u8>, u32)>, 
        cpu_count: usize
    ) -> Vec<thread::JoinHandle<std::result::Result<(), String>>> {
        
        // number of threads used for decryption and decompression
        let c_thread_cnt;
        let e_thread_cnt;
        if crypt_cfg.compress {
            c_thread_cnt = 1.max(cpu_count * 8 / 10);
            e_thread_cnt = 1.max(cpu_count - c_thread_cnt);
        } else {
            c_thread_cnt = 0;
            e_thread_cnt = cpu_count;
        }

        let (tx_e, rx_e) = bounded(cpu_count * 2);

        let mut thread_handles = Vec::with_capacity(cpu_count * 2 + 1);

        // decryption threads
        for _ in 0..e_thread_cnt {
            let cipher_cha= crypt_cfg.cipher_cha.clone();
            let cipher_aes = crypt_cfg.cipher_aes.clone();
            let more_associated_data = crypt_cfg.more_associated_data.clone();
            let rx_in = rx_in.clone();
            let tx_e = if crypt_cfg.compress { tx_e.clone() } else { tx_out.clone() };

            thread_handles.push(thread::spawn( move || -> std::result::Result<(), String> { 
                for (mut buf_inout, chunk_count, final_chunk) in rx_in {
                    Self::aes_decrypt_buffer(&cipher_aes, &mut buf_inout, chunk_count, final_chunk, &more_associated_data)
                        .map_err(|e| e.to_string())?;
                    Self::cha_decrypt_buffer(&cipher_cha, &mut buf_inout, chunk_count, final_chunk, &more_associated_data)
                        .map_err(|e| e.to_string())?;
                    if tx_e.send((buf_inout, chunk_count)).is_err() { break }
                }
                Ok(())
            }));
        }

        if crypt_cfg.compress {
            let (tx_c, rx_c) = bounded(cpu_count * 2);

            // re-segmentation thread
            {
                let rx_e = rx_e.clone();
                let tx_c= tx_c.clone();
                thread_handles.push(thread::spawn( move || -> std::result::Result<(), String> {  
                    Self::resegment(rx_e, tx_c).map_err(|e| e.to_string())?;
                    Ok(())
                }));
            }

            // decompression threads
            for _ in 0..c_thread_cnt {
                let rx_c = rx_c.clone();
                let tx_out = tx_out.clone();

                thread_handles.push(thread::spawn( move || -> std::result::Result<(), String> {
                    for (buf_in, chunk_count) in rx_c {
                        let buf_zip = Self::decompress_buffer(&buf_in).map_err(|e| e.to_string())?;
                        if tx_out.send((buf_zip, chunk_count)).is_err() { break }
                    }
                    Ok(())
                }));
            }
        }        

        thread_handles
    }

    /// Gets unencrypted data of header
    /// 
    /// # Argument:
    /// - `header`: header bytes
    /// 
    /// # Returns:
    /// - `(salt_header_pw, salt_header_enc)`: salts for password, cha/aes keys
    pub fn get_unencrypted_header_items(header_inout: &mut Vec<u8>) -> (Vec<u8>, Vec<u8>) {
        let salt_header_pw  = header_inout.drain(..SALT_SIZE).collect();
        let salt_header_enc = header_inout.drain(..SALT_SIZE).collect();
        (salt_header_pw, salt_header_enc)
    }

    /// Gets encrypted data of header
    /// 
    /// # Argument:
    /// - `enc_header`: encrypted header bytes (without unencrypted bytes)
    /// - `cipher_cha`: cipher struct for chacha decryption
    /// - `cipher_aes`: cipher struct for aes decryption
    /// 
    /// # Returns:
    /// - `Ok((file_format_version, enc_header_params))` contains on success: 
    ///   version of file format, struct of encrypted header parameters
    pub fn get_encrypted_header_items<'a>(enc_header: &'a mut Vec<u8>, cipher_cha: &XChaCha20Poly1305, cipher_aes: &Aes256GcmSiv) -> Result<(u8, EncHeaderParams<'a>)> {
        Self::aes_decrypt_buffer(cipher_aes, enc_header, u32::MAX, true, "header_aes".as_bytes())?;
        Self::cha_decrypt_buffer(cipher_cha, enc_header, 0, false, "header_cha".as_bytes())?;

        // evaluate data
        let file_format_version = enc_header[0];
        let file_format         = enc_header[1];

        let compress = (file_format & 0x01) != 0;
        let archive  = (file_format & 0x02) != 0;
        let keyfile  = (file_format & 0x04) != 0;
        let usb_key  = (file_format & 0x08) != 0;

        let mut s = 2; 
        let mut e = s + SALT_SIZE;
        let salt_body_pw = &enc_header[s..e];
        s = e; e += SALT_SIZE;
        let salt_body_enc = &enc_header[s..e];
         s = e; e += FILE_ID_SIZE;
        let file_id = &enc_header[s..e];

        let mut salt_body_fido = None;
        let mut credential_id_fido = None;
        if usb_key {
            s = e; e += SALT_SIZE;
            salt_body_fido = Some(&enc_header[s..e]);

            let credential_id_fido_len: usize = enc_header[e].into();
            s = e + 1;
            e = s + credential_id_fido_len;
            credential_id_fido = Some(enc_header[s..e].to_vec());
        }

        let enc_header_params = EncHeaderParams {
            salt_body_pw, 
            salt_body_enc,
            file_id,
            salt_body_fido, 
            credential_id_fido, 
            compress, 
            archive, 
            keyfile, 
            usb_key
        };
        Ok((file_format_version, enc_header_params))
    }

    /// Decrypts a file encrypted with dual-layer encryption (AES-256-GCM-SIV + ChaCha20).
    ///
    /// The input must end in `.cce` or `.c00` and contains:
    /// - a short unencrypted header with salts for the password and header keys,
    /// - an encrypted header that declares the body keys and file flags,
    /// - the encrypted body stream, which may be compressed and/or archived.
    ///
    /// The function validates the format version, derives the required keys from the
    /// password and optional key material, decrypts the body in chunks, and writes the
    /// result to the output directory or to a reconstructed file path. When compression
    /// is enabled, it reassembles the compressed fragments and decompresses them before
    /// writing.
    /// 
    /// # Arguments
    /// - `filepath_in`: Path to encrypted input file (must end with `.cce` or `.c00`)
    /// - `dirpath_out`: Option path to an output directory. If `None`, the current working directory is used.
    /// - `keyfilepath`: Optional path to an additional key file
    /// - `verbose`: Verbose output
    /// - `list_archive`: List contents of archive
    ///
    /// # Returns
    /// - `Ok(())` on successful decryption
    /// - `Err` for invalid extensions, missing required key material, unsupported format versions, 
    ///   corrupted headers or payloads, and any I/O or write failure.
    pub fn decrypt(filepath_in: &PathBuf, dirpath_out: Option<&PathBuf>, keyfilepath: Option<&PathBuf>, verbose: bool, list_archive: bool) -> Result<()> {
        if filepath_in.is_dir() {
            return Err("Cannot decrypt a directory".into());
        }

        let mut filepath_out = PathBuf::from(filepath_in.file_name().unwrap());
        if filepath_in.extension() == Some(std::ffi::OsStr::new(ENCRYPTED_FILE_EXT)) ||
           filepath_in.extension() == Some(std::ffi::OsStr::new(SPLIT_ENC_FILE_EXT)) {
            // remove encrypted-file-extension
            filepath_out.set_extension("");
        } else {
            return Err(format!("Invalid filename, it does not end with .{ENCRYPTED_FILE_EXT} or .{SPLIT_ENC_FILE_EXT}").into())
        }

        // set read parameters
        let mut read_input = Box::new( 
            ReadInput::new(
                filepath_in, 
                CHUNK_SIZE + CHA_NONCE_SIZE + CHA_TAG_SIZE + AES_NONCE_SIZE + AES_TAG_SIZE, 
                HEADER_SIZE as u64
            )? 
        );

        // read file header
        let mut header = vec![0u8; HEADER_SIZE];
        read_input.read_files(&mut header)?;

        // get salts of first, unencrypted part of header
        let (salt_header_pw, salt_header_enc) = Self::get_unencrypted_header_items(&mut header);

        // get password and cipher structs for encrypted part of header
        let mut key_builder = KeyBuilder::new(false);
        let (cipher_header_cha, cipher_header_aes) = key_builder.get_password_and_create_header_ciphers(&salt_header_pw, &salt_header_enc)?;

        // decrypt second part of header
        let (file_format_version, enc_header_params) = Self::get_encrypted_header_items(&mut header, &cipher_header_cha, &cipher_header_aes)?;

        // check format version
        if file_format_version != FILE_FORMAT_VERSION {
            return Err(format!(
                "This input file format (v{file_format_version}) cannot be decoded with this app version. It requires file format v{FILE_FORMAT_VERSION}."
            ).into());
        }

        // check if a keyfile is required and provided by user
        if enc_header_params.keyfile && keyfilepath.is_none() {
            return Err("Keyfile missing".into());
        }

        // check for usb key/FIFO authenticator
        if let Some(cred_id_fifo) = enc_header_params.credential_id_fido {
            // usb key was used
            assert!(enc_header_params.usb_key && enc_header_params.salt_body_fido.is_some() && key_builder.credential_id_fido.is_none());
            key_builder.credential_id_fido = Some(cred_id_fifo.to_vec());
        }

        let (cipher_body_cha, cipher_body_aes) = key_builder.create_body_ciphers(enc_header_params.salt_body_pw, enc_header_params.salt_body_enc, keyfilepath, enc_header_params.salt_body_fido)?;

        // use output directory path ot current working directory
        let output_dir =
        if let Some(dir_out) = dirpath_out {
            // create user-specified output directory, if it is not an archive or archive is not just listed (and directory is missing)
            if ((enc_header_params.archive && !list_archive) || !enc_header_params.archive) && !dir_out.exists() {
                fs::create_dir_all(dir_out)?;
            }
            // canonicalize directory, as relative output path elements like ".." might not be resolved
            // in list mode, directory might not exist
            if dir_out.exists() {
                dir_out.canonicalize()?
            } else {
                dir_out.to_path_buf()
            }
        } else {
            env::current_dir()?
        };

        filepath_out = output_dir.join(filepath_out);

        if verbose {
            println!("--------------------------");
            println!("File format version: {}", file_format_version);
            println!("Keyfile:             {}", enc_header_params.keyfile);
            println!("USB security key:    {}", enc_header_params.usb_key);
            println!("Compression:         {}", enc_header_params.compress);
            println!("Archive:             {}", enc_header_params.archive);
            println!("--------------------------");
            if enc_header_params.archive {
                println!("Archive file is extracted to directory {}", output_dir.display());
            } else {
                println!("Output is written to file {}", filepath_out.display());
            }
        }

        // set write parameters and create output file
        let write_output: Box<dyn WriteFiles + Send + 'static> = if enc_header_params.archive {
            // convert relative path elements to absolute ones (looks better for verbose print)
            // in list mode, directory might not exist
            let dirpath_out_absolute = dirpath_out.map(|p| 
                if p.exists() { p.canonicalize() } else { Ok(p.to_path_buf()) }
            ).transpose()?;         
            Box::new( ArchiveWrite::new(dirpath_out_absolute, verbose, list_archive) )
        } else {
            Box::new( WriteOutput::new(filepath_out, vec![])? )
        };

        let crypt_cfg = CryptConfig {
            cipher_cha: cipher_body_cha, 
            cipher_aes: cipher_body_aes, 
            compress: enc_header_params.compress, 
            more_associated_data: enc_header_params.file_id.to_vec()
        }; 
        let crypt_io = CryptIo::new(enc_header_params.archive && (verbose || list_archive));
        crypt_io.io_chunks(&crypt_cfg, Self::decrypt_pipe, read_input, write_output)?;

        Ok(())
    }
}



// ======================================================================
// Unit tests
// ======================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::path;

    #[test]
    fn test_get_unencrypted_header_items() {
        let hdr_org = [[1u8; SALT_SIZE], [2u8; SALT_SIZE], [3u8; SALT_SIZE]].concat();
        let mut hdr = hdr_org.clone();
        let (salt1, salt2) = Decryption::get_unencrypted_header_items(&mut hdr);
        assert_eq!(hdr.len(), SALT_SIZE);
        assert_eq!(salt1, hdr_org[..SALT_SIZE]);
        assert_eq!(salt2, hdr_org[SALT_SIZE..2 * SALT_SIZE]);
        assert_eq!(hdr, hdr_org[2 * SALT_SIZE..])
    }

    #[test]
    fn test_decrypt() {
        // most tests are done together with encryption test

        // file for decryption is too small
        let filepath_in = path::absolute(PathBuf::from("test_dec.cce")).unwrap();
        let data = vec![0xa5; HEADER_SIZE + CHA_NONCE_SIZE + CHA_TAG_SIZE + AES_NONCE_SIZE + AES_TAG_SIZE - 1];
        fs::write(&filepath_in, &data).unwrap();
        assert!(Decryption::decrypt(&filepath_in, None, None, false, false).is_err());

        // empty .cce-file
        fs::write(&filepath_in, []).unwrap();
        assert!(Decryption::decrypt(&filepath_in, None, None, false, false).is_err());

        // cleanup
        let _ = fs::remove_file(&filepath_in);
    }
}