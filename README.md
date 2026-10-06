# cryptcrypt

A command-line tool for encrypting and decrypting a file or a directory using modern encryption algorithms and password-based key derivation.
Additionally, it can use a USB security key, a key file, bzip2 compression and an output file split. The contents of a directory are 
concatenated into an archive.

**Security Notes**: This software is experimental. There wasn't any security audit. Do not use in production. USE AT YOUR OWN RISK!

## Features

- Dual encryption with ciphers AES-GCM-SIV and XChaCha20Poly1305
- Password-based key derivation (Argon2id)
- Optional USB security key / FIDO authenticator to supplement the password
- Optional key file (its first 64 MB) can be used additionally to the password
- Optional bzip2 compression before encryption
- Optional split of output into files of user-defined number and size
- Handles large files efficiently by parallel processing them in chunks
- CLI interface
- Rust toolchain
- Supports MacOS, Linux, Windows

### Archiving supports
- Cross-platform: e.g. an archive created on Linux can be extracted on Windows and vice versa
- Symbolic links
- Hard links
- Sparse files: the size of sparse holes might change on cross-platform extraction
- Modification and access time stamps
- File permissions: only on Unix-like systems (MacOS, Linux)
- Stores relative paths
- Building an archive (i.e. reading files) is done in parallel for improved performance

### USB security key
- FIDO2 authenticator
- PIN must be set on device and need to be entered by user
- Non-discoverable (non-resident) credentials
- Hmac-secret
- Tested with Token2 PIN+ Release3.3  

An encrypted file can be bound to only one USB security key. If you want to protect data against hardware failure of USB security key, you should encrypt the data again with another USB security key.

## Usage

```
Application for encryption and decryption of file or directory.
If no option is given, input is encrypted. Providing a directory creates an encrypted archive.
With option -s the encrypted output is split into files with extensions .c00, .c01, .c02, ...
If a file ending in .c00 is decrypted, the whole split series will be read.

Usage: cryptcrypt [OPTIONS] <FILE_OR_DIRECTORY>

Arguments:
  <FILE_OR_DIRECTORY>  File that should be encrypted or decrypted. If a directory is given, its contents is archived and encrypted

Options:
  -o, --out-dir <OUT_DIR>  Output directory, it is created if it does not exist
  -d, --decrypt            Decrypt file (with extension '.cce' or for split series '.c00')
  -k, --keyfile <KEYFILE>  Additional key file to supplement the password
  -u, --usb-key            Additional USB security key/FIDO authenticator to supplement the password, automatically detected on decryption
  -z, --compress           Compress data before encryption, automatically detected on decryption
  -s, --split <SPLIT>      Split encrypted data into pieces of binary byte sizes (e.g. 2g,3g,1g) [G|g|M|m|K|k]
  -l, --list-archive       List elements of an archive file, do not create its elements
  -v, --verbose            Show details about operations
  -h, --help               Print help
  -V, --version            Print version
```

### Build/Run from Source

```shell
git clone https://github.com/JoergDF/cryptcrypt.git
cd cryptcrypt
cargo run --release
```

### Examples

- Encrypt a file:
  ```
  cryptcrypt file.bin
  ```
  Prompts you to enter a password (with confirmation).  
  Creates output file `file.bin.cce`. Overwrites file, if it already exists.

- Archive and encrypt a directory (with all its sub-directories and files):
  ```
  cryptcrypt directory
  ```
  Creates output file `directory.cce`. Overwrites file, if it already exists.

- Encrypt a file with additional key file, compress and split output files into sizes of 1 KBytes, 2 MBytes and remaining bytes, write output files into folder `output_enc`:
  ```
  cryptcrypt -k keyfile.bin -z -s 1k,2m -o output_enc file.bin
  ```

- Decrypt a file:
  ```
  cryptcrypt -d file.bin.cce
  ```
  Prompts you to enter a password.  
  Creates output file `file.bin`. Overwrites file, if it already exists.

- Decrypt a split series of files with additional key file (compression usage is coded in the encrypted file), write output into folder `output_dec`:
  ```
  cryptcrypt -k keyfile.bin -o output_dec -d file.bin.c00
  ```

## Encryption details

The header of an encrypted file consists of an unencrypted part and an encrypted part:

1. **Unencrypted header part:**  
   It contains two salts used to encrypt the second part of the header: 
   * A random salt used to create a key from the password with [Argon2id](https://github.com/RustCrypto/password-hashes/tree/master/argon2).
   * A different random salt used to derive two keys from that password-derived key using [HKDF-SHA256](https://github.com/RustCrypto/KDFs/tree/master/hkdf). These two final keys are used to encrypt the second header part with [XChaCha20-Poly1305](https://github.com/RustCrypto/AEADs/tree/master/chacha20poly1305) and [AES-256-GCM-SIV](https://github.com/RustCrypto/AEADs/tree/master/aes-gcm-siv).

2. **Encrypted header part:**  
   It contains two new salts used to encrypt the file body and additional metadata:
   * A random salt where the inputs to [Argon2id](https://github.com/RustCrypto/password-hashes/tree/master/argon2) for generating a primary key are: the password, an optional USB security key's hmac-secret, and an optional key file hash.
   * Another random salt used to derive two keys from the primary key using [HKDF-SHA256](https://github.com/RustCrypto/KDFs/tree/master/hkdf). 
   These two keys are used to encrypt the file's body with [XChaCha20-Poly1305](https://github.com/RustCrypto/AEADs/tree/master/chacha20poly1305) and [AES-256-GCM-SIV](https://github.com/RustCrypto/AEADs/tree/master/aes-gcm-siv).  
   
   If a key file is used, its first 64 MB (maximum) is hashed with [sha3-512](https://github.com/RustCrypto/hashes/tree/master/sha3). If a USB security key is used, a credential ID and a random salt are stored and used to retrieve an hmac-secret from the key; otherwise, their space is filled with random data. Additionally, the following data and flags are saved: the file format version, and flags indicating whether compression, an archive, a key file, or a USB security key is used. The overall header length remains constant regardless of which options are selected.

The encryption of the file's body follows this procedure:

1. Read a 1 MB chunk from the input file (the last chunk may be smaller). Keep a zero-based sequence number for each chunk and mark the final chunk with a flag.
2. If compression is enabled, compress the chunk using [bzip2](https://github.com/trifectatechfoundation/bzip2-rs). Its variable-sized output is copied into fixed-size, 1 MB chunks. (The chunk size should not leak information about the cleartext.)
3. **First-pass encryption:** Encrypt the chunk with [XChaCha20-Poly1305](https://github.com/RustCrypto/AEADs/tree/master/chacha20poly1305) using a fresh random base nonce generated per chunk. The implementation derives the actual encryption nonce by XOR'ing the base nonce with the chunk's sequence number and the final-chunk flag. The original base nonce is stored after the ChaCha ciphertext so the per-chunk nonce can be recomputed during decryption. Reordering or truncating the chunk sequence causes a decryption error. Additional associated data (AAD) used for authentication includes: the file format version, the string "Cha", and the file ID.
4. **Second-pass encryption:** Encrypt the output of step 3 with [AES-256-GCM-SIV](https://github.com/RustCrypto/AEADs/tree/master/aes-gcm-siv) using a fresh random nonce. AAD contains: the file format version, the string "Aes", the file ID, the chunk count, and the final flag. The AES nonce is stored after the AES ciphertext and written to the output file.
5. Repeat steps 1 through 4 until all input is processed.


## License

This project is licensed under either of

 - [Apache License, Version 2.0](./LICENSE-APACHE)
 - [MIT license](./LICENSE-MIT)

at your option.

