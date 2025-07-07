# Image File Encryption and Decryption System

A secure C-based command-line tool for encrypting and decrypting JPG and PNG image files using AES-256-GCM encryption with OpenSSL.

Features

- Strong Encryption**: Uses AES-256-GCM (Galois/Counter Mode) for authenticated encryption
- Image Format Support**: Handles JPG/JPEG and PNG image files
- Format Detection**: Automatically detects and validates image file formats
- Custom File Format**: Creates encrypted files with custom signature and metadata
- Secure Key Generation**: Uses OpenSSL's cryptographically secure random number generator
- Authentication**: Includes GCM authentication tags to prevent tampering
- Cross-Platform**: Works on Windows with Visual Studio Build Tools

Security Features

- AES-256-GCM Encryption**: Industry-standard authenticated encryption
- Random IV Generation**: Each encryption uses a unique initialization vector
- Authentication Tags**: Ensures data integrity and authenticity
- Secure Random Keys**: Uses OpenSSL's RAND_bytes for cryptographically secure randomness
- File Format Validation**: Verifies input files are valid images before encryption

## Requirements

Windows
- Visual Studio Build Tools 2022 (or Visual Studio 2022)
- OpenSSL library (installed via vcpkg recommended)
- vcpkg package manager

Dependencies
- OpenSSL development libraries
- Windows SDK

## Installation

1. Install Visual Studio Build Tools
Download and install Visual Studio Build Tools 2022 from Microsoft's official website.

2. Install vcpkg
```bash
git clone https://github.com/Microsoft/vcpkg.git
cd vcpkg
.\bootstrap-vcpkg.bat
```

3. Install OpenSSL via vcpkg
```bash
.\vcpkg install openssl:x64-windows
```

4. Clone this repository
```bash
git clone https://github.com/yourusername/Image-File-Encryption-and-Decryption-System.git
cd Image-File-Encryption-and-Decryption-System
```

5. Update paths in run.bat
Edit `run.bat` and update the vcpkg path to match your installation:
```batch
set "INCLUDE=%INCLUDE%;C:\path\to\your\vcpkg\installed\x64-windows\include"
set "LIB=%LIB%;C:\path\to\your\vcpkg\installed\x64-windows\lib"
```

Compilation

Using the provided batch file (Windows)
```bash
run.bat
```

Manual compilation (Windows)
```bash
cl c.c /I"C:\path\to\vcpkg\installed\x64-windows\include" /link /LIBPATH:"C:\path\to\vcpkg\installed\x64-windows\lib" libssl.lib libcrypto.lib
```

## Usage

Basic Syntax
```bash
c.exe [encrypt|decrypt] [input_file] [output_file] [key(optional)]
```

Encryption Examples
```bash
# Encrypt with auto-generated key
c.exe encrypt photo.jpg encrypted.bin

# Encrypt with custom key
c.exe encrypt image.png encrypted.bin "my32characterlongencryptionkey!"
```

Decryption Examples
```bash
# Decrypt with provided key
c.exe decrypt encrypted.bin recovered.jpg "my32characterlongencryptionkey!"

# The tool will automatically add the correct file extension if missing
c.exe decrypt encrypted.bin recovered "my32characterlongencryptionkey!"
```

## Key Management

- Auto-generated keys: If no key is provided, a cryptographically secure 32-byte key is generated and displayed
- Custom keys: Must be at least 32 characters long
- **Key storage: Keys are not stored by the program - you must save them securely
- **Key format: Keys are displayed in hexadecimal format for easy copying

## File Format

The encrypted file format includes:
1. Signature: 8-byte custom signature (`IMGENCRY`)
2. Format byte: Original image format identifier (0x01 for JPG, 0x02 for PNG)
3. IV: 16-byte initialization vector
4. GCM Tag: 16-byte authentication tag
5. Encrypted data: The actual encrypted image data

## Example Output

# Encryption
```
Image Format: JPEG
Encryption IV: 297164093a4d06669d83828f2169db3
Encrypted 1350009 bytes of image data
Authentication tag: e5381351faa8c6551e5b49371185if96
Operation completed successfully!
```

# Decryption
```
Detected original format: JPEG
Decryption IV: 297164093a4d06669d83828f2169db3
Authentication tag: e5381351faa8c6551e5b49371185if96
Decrypted 1350009 bytes to JPEG image
Operation completed successfully!
```

## Error Handling

The program includes comprehensive error handling for:
- Invalid file formats
- Corrupted encrypted files
- Incorrect decryption keys
- File I/O errors
- Memory allocation failures
- OpenSSL library errors

## Security Considerations

- **Key Security**: Store encryption keys securely and never share them
- **Key Length**: Always use keys of at least 32 characters
- **File Integrity**: The GCM authentication tag ensures file integrity
- **Secure Deletion**: Consider securely deleting original files after encryption
- **Backup**: Always keep secure backups of your encryption keys

## Limitations

- Only supports JPG/JPEG and PNG image formats
- Keys must be at least 32 characters long
- Requires OpenSSL library installation
- Currently optimized for Windows with Visual Studio

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is open source. Please check the LICENSE file for details.

## Support

For issues and questions:
1. Check the error messages - they provide specific guidance
2. Ensure all dependencies are properly installed
3. Verify file paths and permissions
4. Create an issue on GitHub with detailed error information

## Technical Details

- **Encryption Algorithm**: AES-256-GCM
- **Key Size**: 256 bits (32 bytes)
- **IV Size**: 128 bits (16 bytes)
- **Authentication Tag**: 128 bits (16 bytes)
- **Supported Formats**: JPG, JPEG, PNG
- **Platform**: Windows (Visual Studio Build Tools)

## Changelog

### Version 1.0
- Initial release
- AES-256-GCM encryption support
- JPG and PNG format support
- Custom encrypted file format
- Secure key generation
- Comprehensive error handling
