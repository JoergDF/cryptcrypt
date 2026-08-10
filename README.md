# cryptcrypt

A command-line tool for encrypting and decrypting a file or a directory using modern encryption algorithms and password-based key derivation.
Additionally, it can use a key file, bzip2 compression and an output file split. The contents of a directory are concatenated into an archive.

**Security Notes**: This software is experimental. There wasn't any security audit. Do not use in production. USE AT YOUR OWN RISK!

## Features

- Dual encryption with ciphers AES-GCM-SIV and XChaCha20Poly1305
- Password-based key derivation (Argon2id)
- Optional key file can be used additionally to the password
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

1. If a key file is used, hash its first 64 MByte (maximum) with [sha3-512](https://github.com/RustCrypto/hashes/tree/master/sha3).
2. Derive encryption key from password and the optional key file hash using Argon2id with a random salt. Write the salt to the output file.
3. From the master key derive two independent 32‑byte keys: one for XChaCha20-Poly1305 and one for AES-256-GCM-SIV. 
Each key is derived with [HKDF-SHA256](https://github.com/RustCrypto/KDFs/tree/master/hkdf) using its own fresh random salt. 
Write the ChaCha salt then the AES salt immediately after the password salt.
4. Encrypt and write file format version and file format (i.e. compression status) to the output file. (file header: password salt, ChaCha salt, AES salt, encrypted file format version, encrypted file format).
5. Read a 1 MByte chunk from the input file (the last chunk may be smaller). 
Keep a zero-based sequence number for each chunk and mark the final chunk with a flag.
6. If compression is switched on, compress chunk with bzip2. Its variably sized output is copied to fixed sized, 1 MB chunks. The chunk size should not give a hint about the cleartext.
7. First-pass encrypt the chunk with [XChaCha20-Poly1305](https://github.com/RustCrypto/AEADs/tree/master/chacha20poly1305) 
using a fresh random base nonce generated per chunk. For the actual encryption nonce the implementation derives a per-chunk nonce 
by XOR’ing the base nonce with the chunk’s sequence number and the final-chunk flag; the original base nonce is stored before the 
ChaCha ciphertext so the per-chunk nonce can be recomputed during decryption. Reordering or truncating the chunk sequence would cause a decryption error.
8. Second-pass encrypt the output of step 7 with [AES-256-GCM-SIV](https://github.com/RustCrypto/AEADs/tree/master/aes-gcm-siv) 
using a fresh random nonce; the AES nonce is stored before the AES ciphertext and written to the (split) output file.
9. Repeat steps 5–8 until all input is processed.

## License

This project is licensed under either of

 - [Apache License, Version 2.0](./LICENSE-APACHE)
 - [MIT license](./LICENSE-MIT)

at your option.

