# cryptcrypt

A command-line tool for encrypting and decrypting a file using modern encryption algorithms and password-based key derivation.

**Security Notes**: This software is experimental. There wasn't any security audit. Do not use in production. USE AT YOUR OWN RISK!

## Features

- Dual encryption with ciphers AES-GCM-SIV and XChaCha20Poly1305
- Password-based key derivation (Argon2id)
- Handles large files efficiently by parallel processing them in chunks
- CLI interface
- Rust toolchain
- For MacOS, Linux, Windows


## Usage

```
Program for encryption and decryption of a file. 
If no option is given, the file is encrypted.

Usage: cryptcrypt [OPTIONS] <FILE>

Arguments:
	<FILE>  File that should be encrypted or decrypted

Options:
	-d, --decrypt  Decrypt file
	-h, --help     Print help
	-V, --version  Print version
```

### Build/Run from Source

```
git clone https://github.com/JoergDF/cryptcrypt.git
cd cryptcrypt
cargo run --release
```

### Examples

- Show help:
  ```
  cargo r -r -- --help
  ```

- Encrypt a file:
  ```
  cargo r -r -- file.bin
  ```
  Prompts you to enter a password (with confirmation).  
  Creates output file `file.bin.cce`. Overwrites file, if it already exists.

- Decrypt a file:
  ```
  cargo r -r -- -d file.bin.cce
  ```
  Prompts you to enter a password.  
  Creates output file `file.bin`. Overwrites file, if it already exists.


## Encryption details

1. Derive encryption key from password using Argon2id with a random salt. Write the salt to the start of the encrypted file.
2. Read a 1 MByte chunk from the input file.
3. Encrypt chunk with [XChaCha20Poly1305](https://github.com/RustCrypto/AEADs/tree/master/chacha20poly1305) using the key from step 1 and a random nonce. Place the nonce before the encrypted data.
4. Encrypt the result from step 3 with [AES-GCM-SIV](https://github.com/RustCrypto/AEADs/tree/master/aes-gcm-siv) using a random nonce and a new key derived from step 1's key using [HKDF-SHA256](https://github.com/RustCrypto/KDFs/tree/master/hkdf) and a random HKDF-info. Place both the HKDF-info and nonce before the encrypted data.
5. Write the encrypted result to the output file.
6. Repeat steps 2–5 until all input data is encrypted.


## License

This project is licensed under the [MIT license](./LICENSE).


