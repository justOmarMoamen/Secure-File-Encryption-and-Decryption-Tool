# Secure File Encryption Tool

## Overview

This is a robust, Python-based command-line encryption tool designed to provide secure file encryption and decryption using advanced cryptographic techniques.

## Features

- **Strong Encryption**: AES-GCM encryption (128-bit and 256-bit key sizes)
- **Secure Key Derivation**: Argon2id key derivation algorithm
- **Data Integrity**: HMAC-SHA256 authentication
- **File Compression**: Integrated zlib compression
- **Cross-Platform**: Works on Windows, macOS, and Linux
- **Brute Force Protection**: Limited decryption attempts

## Prerequisites

- Python 3.8+
- Required Libraries:
  - PyCryptoDome
  - argon2-cffi

## Installation

1. Clone the repository:
```bash
git clone https://github.com/justOmarMoamen/Secure-File-Encryption-and-Decryption-Tool.git
cd Secure-FIle-Encryption
```

2. Install dependencies:
```bash
pip install pycryptodome argon2-cffi
```

## Usage

### Encryption

Encrypt a file using a password:
```bash
python encryption_tool.py encrypt /path/to/file.txt -p "YourSecurePassword"
```
```bash
python encryption_tool.py encrypt /path/to/file.txt -p "YourSecurePassword" -o <path_to_custom_file/<encrypted_file>.enc>
```
```bash
python encryption_tool.py encrypt --key-size [16, 32] /path/to/file.txt -p "YourSecurePassword" -o <path_to_custom_file/<encrypted_file>.enc>
```

#### Optional Encryption Parameters
- `-h, --help`: Show help message and exit
- `--time`: Argon2 time cost (default: 2)
- `--memory`: Memory cost in KB (default: 65536)
- `--key-size`: AES key size (16 for AES-128, 32 for AES-256)
- `-p`: Password for encryption/decryption
- `-v`: Enable verbose output
- `-o`: Custom output file path

### Decryption

Decrypt an encrypted file:
```bash
python encryption_tool.py decrypt /path/to/file.txt.enc -p "YourSecurePassword"
```
```bash
python encryption_tool.py decrypt /path/to/file.txt -p "YourSecurePassword" -o <path_to_custom_file/<decrypted_file>.txt>
```
```bash
python encryption_tool.py decrypt --key-size [16, 32] /path/to/file.txt -p "YourSecurePassword" -o <path_to_custom_file/<decrypted_file>.txt>
```

## Security Mechanisms

### 1. Key Derivation (Argon2id)
- Protects against:
  - Rainbow table attacks
  - Dictionary attacks
  - Precomputed hash attacks

### 2. Encryption (AES-GCM)
- Provides:
  - Confidentiality
  - Authenticity
  - Integrity

### 3. HMAC Verification
- Ensures data hasn't been tampered with
- Prevents unauthorized modifications

## Threat Model and Limitations

### Strengths
- Strong key derivation
- Authenticated encryption
- Memory-hard key stretching
- Compression before encryption

### Limitations
- Vulnerable to:
  - Weak passwords
  - Keyloggers
  - Physical device compromise
  - Side-channel attacks

### Not Protected Against
- Network-level attacks
- Advanced persistent threats
- Rubber hose cryptanalysis

## Performance Considerations

- Encryption/Decryption speed depends on:
  - File size
  - Memory and time cost parameters
  - Hardware specifications

### Recommended Parameters
- Time Cost: 2-4
- Memory Cost: 2^16 KB (64 MB)
- Adjust based on your performance needs

## Best Practices

1. Use strong, unique passwords
2. Store passwords securely
3. Use key files or multi-factor authentication
4. Regularly update the tool
5. Be aware of your threat model

## Error Handling

- Maximum 3 decryption attempts
- Verbose error messages
- Secure failure modes

## Troubleshooting

- **Decryption Failure**: 
  - Verify correct password
  - Check file integrity
  - Ensure no file corruption

- **Performance Issues**:
  - Reduce memory/time cost
  - Use on more powerful hardware

## Contribution

### Reporting Issues
- Open GitHub issues
- Provide detailed error logs
- Include system information

### Security Vulnerabilities
- Responsible disclosure via email
- Provide detailed, reproducible steps


## Disclaimer

THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY. USE AT YOUR OWN RISK.
