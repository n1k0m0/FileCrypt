# FileCrypt

Small console application to encrypt and decrypt files with AES using a password. It uses the .NET crypto API and stores an integrity tag (HMAC-SHA512) in the file header so tampering can be detected.

> Target runtime: .NET Framework 4.8  
> License: Apache-2.0

---

## Features

- AES-256 in CBC mode with PKCS7 padding
- Password-based key derivation via PBKDF2 (SHA-512, 50,000 iterations)
- HMAC-SHA512 integrity protection stored in the file header
- Streaming I/O in fixed-size blocks (low memory footprint)
- Progress indicator and throughput display

---

## Quick Start

### Encrypt

```bash
FileCrypt encrypt <InputFileName> <OutputFileName>
```

The program will ask for a password and a repetition for confirmation. The output file is created new and must not already exist.

### Decrypt

```bash
FileCrypt decrypt <InputFileName> <OutputFileName>
```

Enter the same password that was used for encryption. After decryption completes, the program verifies the HMAC and prints whether it is valid.

---

## Detailed Usage

### Command-line syntax

```
FileCrypt encrypt <input> <output>
FileCrypt decrypt <input> <output>
```

Parameters:
- `<input>`  Path to the source file to read.
- `<output>` Path to the destination file to create. The file must not exist yet.

### Prompts

- `Password:` The password to derive encryption and HMAC keys from.
- `Repeat  :` Repeat the password to avoid typos.

### Output and status

- During processing, a progress line is updated once per second and shows a percentage and an approximate throughput.
- On decryption, after writing the plaintext the program computes an HMAC and compares it to the header value:
  - `HMAC is valid. File was not manipulated`
  - `HMAC is invalid. File was probably manipulated`

### Exit behavior

- Errors are printed to the console as `Exception occured: <message>`.
- The program does not set specific exit codes; check console output for success or failure messages.

---

## How It Works

### Algorithms and parameters

- **Key derivation:** PBKDF2 with SHA-512, 50,000 iterations, 16-byte random salt  
  - Derived bytes: 32 bytes for AES key, followed by 32 bytes for HMAC key.
- **Encryption:** AES-256, CBC mode, PKCS7 padding, 16-byte random IV.
- **Integrity:** HMAC-SHA512 (64 bytes).

### File format

The encrypted file begins with a fixed header:

```
[ IV (16 bytes) ][ SALT (16 bytes) ][ HMAC (64 bytes) ][ CIPHERTEXT (... bytes) ]
```

- `IV` is used for AES-CBC.
- `SALT` is used by PBKDF2.
- `HMAC` is the HMAC-SHA512 over the plaintext. It is computed in a streaming fashion during processing.
- `CIPHERTEXT` is the AES-CBC encrypted payload of the input file.

Header size: 96 bytes total.

### Streaming HMAC

- **During encryption:** While reading plaintext blocks from the input, the program updates an HMAC state. Because the final HMAC is not known upfront, a 64-byte placeholder is written in the header. After encryption finishes, the program seeks back and overwrites the placeholder with the final HMAC value.
- **During decryption:** While reading plaintext blocks from the decrypting `CryptoStream`, the program updates an HMAC state and, at the end, compares the computed value to the header’s HMAC.

Note: The HMAC here authenticates the plaintext content. If the ciphertext or header is modified, decryption will produce incorrect plaintext and the HMAC check will fail.

---

## Building

### Prerequisites

- Windows with .NET Framework 4.8 development tools
- Visual Studio 2019 or newer (with .NET Framework 4.8 targeting pack) or MSBuild

### Visual Studio

1. Create or open a Console App (.NET Framework) project targeting .NET Framework 4.8.
2. Replace the generated `Program.cs` with the provided source.
3. Build the solution in Release mode.

### MSBuild

If you have a `.csproj` targeting .NET Framework 4.8:

```bash
msbuild /p:Configuration=Release
```

The resulting executable will be in `bin\Release`.

---

## Examples

### Encrypt a large log file

```bash
FileCrypt encrypt server.log server.log.enc
```

- You will be prompted twice for the password.
- The output file `server.log.enc` will contain the 96-byte header followed by the ciphertext.

### Decrypt the file back

```bash
FileCrypt decrypt server.log.enc server_restored.log
```

- Enter the same password.
- After completion, the program prints the HMAC verification result.

---

## Operational Notes

- **Buffer size:** The program uses a 40 KB read/write buffer for efficient streaming.
- **File creation:** The output file is created with `CreateNew`; if it already exists, the operation fails.
- **Password handling:** The password is read without echoing; only asterisks are shown.
- **RNG:** IV and salt are generated via `RNGCryptoServiceProvider`.

---

## Security Considerations

- This tool demonstrates traditional encrypt-and-MAC with separate keys derived from the same password and salt. The HMAC in this implementation authenticates the plaintext, not the ciphertext. For modern production scenarios, consider authenticated encryption with associated data (AEAD), such as AES-GCM or ChaCha20-Poly1305, which provides encryption and integrity in one step.
- The integrity tag is stored in the header. An attacker without the password cannot forge a valid HMAC for modified plaintext.
- Password strength matters. Use sufficiently long, high-entropy passwords. The PBKDF2 iteration count is 50,000, which increases the cost of brute-force attacks. Adjust as needed for your environment.

---

## Troubleshooting

- `Entered passwords did not match!`  
  Re-run and type the same password twice.

- `HMAC is invalid. File was probably manipulated`  
  The password may be wrong, the file may be corrupted, or it was modified. Verify the password and the integrity of the input file.

- `The process cannot create a file when that file already exists.`  
  Choose a different output path; the tool will not overwrite files.

- `Exception occured: ...`  
  Read the full message for details such as access permissions, missing files, or invalid arguments.

---

## License

Licensed under the Apache License, Version 2.0. See the `LICENSE` file or https://www.apache.org/licenses/LICENSE-2.0 for details.

---

## Acknowledgments

Original author: Nils Kopal  
Project idea and educational focus: CrypTool.org context
