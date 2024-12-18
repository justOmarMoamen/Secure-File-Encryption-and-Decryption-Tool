import argparse
import os
import sys
import hmac
import hashlib
import zlib
from typing import Tuple, Optional

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from argon2.low_level import hash_secret_raw, Type

# Constants for security and performance
BUFFER_SIZE = 64 * 1024  # 64KB buffer for efficient file processing
MAX_DECRYPT_ATTEMPTS = 3  # Limit decryption attempts to prevent brute force
SALT_SIZE = 16  # Bytes for salt
NONCE_SIZE = 12  # Bytes for nonce (standard for AES-GCM)
HMAC_SIZE = 32  # SHA-256 HMAC size

class EncryptionError(Exception):
    """Custom exception for encryption-related errors."""
    pass

def secure_random_bytes(length: int) -> bytes:
    """
    Generate cryptographically secure random bytes.
    
    Args:
        length (int): Number of random bytes to generate.
    
    Returns:
        bytes: Cryptographically secure random bytes.
    """
    return get_random_bytes(length)

def derive_key(password: str, salt: bytes, 
               time_cost: int = 2, 
               memory_cost: int = 2**16, 
               parallelism: int = 1, 
               hash_len: int = 32) -> bytes:
    """
    Derive a secure encryption key using Argon2id.
    
    Args:
        password (str): User-provided password.
        salt (bytes): Cryptographic salt.
        time_cost (int): CPU cost parameter.
        memory_cost (int): Memory usage.
        parallelism (int): Number of parallel threads.
        hash_len (int): Length of derived key.
    
    Returns:
        bytes: Derived cryptographic key.
    """
    return hash_secret_raw(
        secret=password.encode('utf-8'),
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=hash_len,
        type=Type.ID  # Argon2id variant
    )

def compress_data(data: bytes) -> bytes:
    """
    Compress data using zlib for efficient storage.
    
    Args:
        data (bytes): Input data to compress.
    
    Returns:
        bytes: Compressed data.
    """
    return zlib.compress(data, level=zlib.Z_BEST_COMPRESSION)

def decompress_data(compressed_data: bytes) -> bytes:
    """
    Decompress previously compressed data.
    
    Args:
        compressed_data (bytes): Compressed input data.
    
    Returns:
        bytes: Decompressed original data.
    """
    return zlib.decompress(compressed_data)

def compute_hmac(key: bytes, data: bytes) -> bytes:
    """
    Compute HMAC-SHA256 for data integrity verification.
    
    Args:
        key (bytes): HMAC key.
        data (bytes): Data to authenticate.
    
    Returns:
        bytes: HMAC authentication tag.
    """
    return hmac.new(key, data, hashlib.sha256).digest()

def verify_hmac(key: bytes, data: bytes, expected_hmac: bytes) -> bool:
    """
    Verify data integrity using HMAC.
    
    Args:
        key (bytes): HMAC verification key.
        data (bytes): Data to verify.
        expected_hmac (bytes): Original HMAC for comparison.
    
    Returns:
        bool: True if HMAC matches, False otherwise.
    """
    computed_hmac = compute_hmac(key, data)
    return hmac.compare_digest(computed_hmac, expected_hmac)

def validate_file(file_path: str) -> bool:
    """
    Validate input file exists and is accessible.
    
    Args:
        file_path (str): Path to the input file.
    
    Returns:
        bool: True if file exists and is readable, False otherwise.
    """
    if not os.path.exists(file_path):
        print(f"[-] Error: File not found - {file_path}")
        return False
    
    if not os.path.isfile(file_path):
        print(f"[-] Error: Not a valid file - {file_path}")
        return False
    
    if not os.access(file_path, os.R_OK):
        print(f"[-] Error: Unable to read file - {file_path}")
        return False
    
    return True

def encrypt_file(input_file: str, 
                 password: str, 
                 time_cost: int = 2, 
                 memory_cost: int = 2**16, 
                 key_size: int = 32, 
                 verbose: bool = False,
                 output_file: Optional[str] = None) -> None:
    """
    Encrypt file with advanced security features.
    
    Args:
        input_file (str): Path to file to encrypt.
        password (str): Encryption password.
        time_cost (int): Argon2 time cost.
        memory_cost (int): Argon2 memory cost.
        key_size (int): Encryption key size.
        verbose (bool): Enable detailed logging.
        output_file (Optional[str]): Custom output file path.
    
    Raises:
        EncryptionError: If encryption fails.
    """
    try:
        if not validate_file(input_file):
            sys.exit(1)
        
        # Determine output file path
        if output_file is None:
            output_file = input_file + ".enc"
        
        # Cryptographic randomness
        salt = secure_random_bytes(SALT_SIZE)
        nonce = secure_random_bytes(NONCE_SIZE)
        
        # Derive keys
        encryption_key = derive_key(password, salt, time_cost, memory_cost, hash_len=key_size)
        hmac_key = secure_random_bytes(key_size)
        
        with open(input_file, 'rb') as infile, open(output_file, 'wb') as outfile:
            # Read entire file for compression and HMAC
            raw_data = infile.read()
            compressed_data = compress_data(raw_data)
            
            # Create cipher
            cipher = AES.new(encryption_key, AES.MODE_GCM, nonce=nonce)
            encrypted_data, tag = cipher.encrypt_and_digest(compressed_data)
            
            # Compute HMAC
            hmac_tag = compute_hmac(hmac_key, encrypted_data)
            
            # Write cryptographic metadata and encrypted data
            outfile.write(salt)          # 16 bytes
            outfile.write(nonce)          # 12 bytes
            outfile.write(tag)            # 16 bytes
            outfile.write(hmac_key)       # 32 bytes
            outfile.write(hmac_tag)       # 32 bytes
            outfile.write(encrypted_data)
        
        if verbose:
            print(f"[+] File encrypted successfully: {output_file}")
        
        # Securely clear sensitive data from memory
        del encryption_key, hmac_key, raw_data, compressed_data, encrypted_data
    
    except Exception as e:
        print(f"Encryption failed: {e}")
        sys.exit(1)

def decrypt_file(input_file: str, 
                 password: Optional[str] = None, 
                 time_cost: int = 2, 
                 memory_cost: int = 2**16, 
                 key_size: int = 32, 
                 verbose: bool = False,
                 output_file: Optional[str] = None) -> bool:
    """
    Decrypt file with robust integrity checks and interactive password entry.
    
    Args:
        input_file (str): Path to encrypted file.
        password (str, optional): Decryption password.
        time_cost (int): Argon2 time cost.
        memory_cost (int): Argon2 memory cost.
        key_size (int): Encryption key size.
        verbose (bool): Enable detailed logging.
        output_file (Optional[str]): Custom output file path.
    
    Returns:
        bool: True if decryption successful, False otherwise.
    """
    if not validate_file(input_file):
        return False
    
    # Determine output file path
    if output_file is None:
        output_file = input_file.replace('.enc', '.dec')
    
    try:
        with open(input_file, 'rb') as infile:
            # Read cryptographic metadata
            salt = infile.read(SALT_SIZE)
            nonce = infile.read(NONCE_SIZE)
            tag = infile.read(16)  # AES-GCM tag
            hmac_key = infile.read(key_size)
            stored_hmac = infile.read(HMAC_SIZE)
            encrypted_data = infile.read()
            
            # Interactive password handling
            max_attempts = 3
            for attempt in range(max_attempts):
                # Use provided password or prompt for input
                if password is None:
                    try:
                        password = input(f"Enter decryption password (Attempt {attempt + 1}/{max_attempts}): ")
                    except KeyboardInterrupt:
                        print("\n[!] Decryption cancelled.")
                        return False
                
                # Verify HMAC before decryption
                if not verify_hmac(hmac_key, encrypted_data, stored_hmac):
                    print("[-] Data integrity check failed. File may be tampered.")
                    return False
                
                # Derive decryption key using Argon2
                try:
                    decryption_key = derive_key(password, salt, time_cost, memory_cost, hash_len=key_size)
                    
                    # Attempt decryption
                    cipher = AES.new(decryption_key, AES.MODE_GCM, nonce=nonce)
                    compressed_data = cipher.decrypt_and_verify(encrypted_data, tag)
                    
                    # Decompress data
                    decrypted_data = decompress_data(compressed_data)
                    
                    # Write decrypted file
                    with open(output_file, 'wb') as outfile:
                        outfile.write(decrypted_data)
                    
                    if verbose:
                        print(f"[+] File decrypted successfully: {output_file}")
                    
                    # Securely clear sensitive data from memory
                    del decryption_key, compressed_data, decrypted_data
                    
                    return True
                
                except ValueError:
                    # Decryption failed - likely incorrect password
                    print(f"[-] Decryption failed. Invalid password. {max_attempts - attempt - 1} attempts remaining.")
                    password = None  # Reset password for next iteration
                
                # Clear sensitive memory
                del decryption_key
            
            # Max attempts exceeded
            print("[-] Maximum decryption attempts reached. Decryption failed.")
            return False
    
    except Exception as e:
        print(f"Decryption error: {e}")
        return False

def parse_arguments() -> Optional[argparse.Namespace]:
    """
    Parse and validate command-line arguments.
    
    Returns:
        Optional[argparse.Namespace]: Parsed arguments or None if invalid.
    """
    parser = argparse.ArgumentParser(
        description="🔒 Advanced Secure File Encryption Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Encryption:
    python Secure-File-Encryption.py encrypt secret.txt -p mypassword
    python Secure-File-Encryption.py encrypt large_file.zip -p strong_pass -o output.enc

  Decryption:
    python Secure-File-Encryption.py decrypt secret.txt.enc -p mypassword
    python Secure-File-Encryption.py decrypt large_file.zip.enc -p strong_pass -o decrypted_file.txt -v

Security Features:
  - AES-256 Encryption with Galois/Counter Mode (GCM)
  - Argon2id Key Derivation (Resistant to side-channel attacks)
  - HMAC Integrity Verification
  - Cryptographically Secure Random Bytes
  - Optional Compression
"""
    )
    
    # Ensure help is shown if no arguments are provided
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        return None

    parser.add_argument("mode", 
                        choices=["encrypt", "decrypt"], 
                        help="Operation mode: 'encrypt' or 'decrypt' a file")
    parser.add_argument("file", 
                        help="Path to input file (to encrypt or decrypt)")
    parser.add_argument("-p", "--password", 
                        required=True, 
                        help="Password for encryption/decryption")
    parser.add_argument("-o", "--output", 
                        help="Custom output file path")
    parser.add_argument("--time", 
                        type=int, 
                        default=2, 
                        help="Argon2 time cost (default: 2)")
    parser.add_argument("--memory", 
                        type=int, 
                        default=2**16, 
                        help="Argon2 memory cost in KB (default: 65536)")
    parser.add_argument("--key-size", 
                        type=int, 
                        choices=[16, 32], 
                        default=32, 
                        help="AES key size: 16 (AES-128) or 32 (AES-256, default)")
    parser.add_argument("-v", "--verbose", 
                        action="store_true", 
                        help="Enable detailed logging")

    try:
        args = parser.parse_args()
        
        # Additional validation for mode-specific requirements
        if args.mode == "encrypt":
            if not validate_file(args.file):
                return None
            
            # Validate output file path if provided
            if args.output:
                output_dir = os.path.dirname(args.output)
                if output_dir and not os.path.exists(output_dir):
                    print(f"[-] Error: Output directory does not exist - {output_dir}")
                    return None
        
        if args.mode == "decrypt":
            if not args.file.endswith('.enc'):
                print("[-] Error: Encrypted files must have '.enc' extension")
                return None
            
            if not validate_file(args.file):
                return None
            
            # Validate output file path if provided
            if args.output:
                output_dir = os.path.dirname(args.output)
                if output_dir and not os.path.exists(output_dir):
                    print(f"[-] Error: Output directory does not exist - {output_dir}")
                    return None
        
        return args
    
    except SystemExit:
        # Capture argparse's default help/error behavior
        return None

def main():
    """
    Main entry point for the Secure File Encryption Tool.
    Handles argument parsing and routing to encryption/decryption.
    """
    args = parse_arguments()
    
    if args is None:
        # If arguments are invalid or help was requested, exit gracefully
        print("\n[!] Please provide valid arguments. See usage above.")
        sys.exit(1)
    
    try:
        if args.mode == "encrypt":
            encrypt_file(args.file, args.password, args.time, 
                         args.memory, args.key_size, args.verbose, 
                         output_file=args.output)
        else:
            decrypt_file(args.file, args.password, args.time, 
                         args.memory, args.key_size, args.verbose, 
                         output_file=args.output)
    except Exception as e:
        print(f"Operation failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()