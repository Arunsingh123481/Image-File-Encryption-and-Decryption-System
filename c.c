#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <ctype.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define BUFFER_SIZE 1024
#define KEY_SIZE 32  
#define IV_SIZE 16   
#define SIGNATURE_SIZE 8 
#define AES_BLOCK_SIZE 16 
#define GCM_TAG_SIZE 16 

// File signatures (magic numbers)
const unsigned char JPG_SIGNATURE[] = {0xFF, 0xD8, 0xFF};
const unsigned char PNG_SIGNATURE[] = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};

// Our custom encrypted file signature
const unsigned char ENCRYPTED_SIGNATURE[] = {'I', 'M', 'G', 'E', 'N', 'C', 'R', 'Y'};

// Image file format
typedef enum {
    FORMAT_UNKNOWN,
    FORMAT_JPG, 
    FORMAT_PNG
} ImageFormat;

// Function prototypes
void generate_key(unsigned char *key, int size);
bool encrypt_image(const char *input_file, const char *output_file, const unsigned char *key);
bool decrypt_image(const char *input_file, const char *output_file, const unsigned char *key);
ImageFormat detect_image_format(FILE *file);
void print_usage(const char *program_name);
void print_hex(const unsigned char *data, size_t len);
bool is_valid_image_extension(const char *filename);
int aes_gcm_encrypt(unsigned char *plaintext, int plaintext_len, 
                    const unsigned char *key, const unsigned char *iv, int iv_len,
                    unsigned char *ciphertext, unsigned char *tag);
int aes_gcm_decrypt(unsigned char *ciphertext, int ciphertext_len, 
                    const unsigned char *tag,
                    const unsigned char *key, const unsigned char *iv, int iv_len,
                    unsigned char *plaintext);
void handle_openssl_error();

int main(int argc, char *argv[]) {
    //OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    
    if (argc < 4) {
        print_usage(argv[0]);
        return 1;
    }

    char *mode = argv[1];
    char *input_file = argv[2];
    char *output_file = argv[3];
    unsigned char key[KEY_SIZE];
    
    // Check if key is provided or should be generated
    if (argc == 5) {
        // Use provided key
        if (strlen(argv[4]) < KEY_SIZE) {
            printf("Error: Key must be at least %d characters long\n", KEY_SIZE);
            return 1;
        }
        memcpy(key, argv[4], KEY_SIZE);
    } else {
        // Generate random key
        generate_key(key, KEY_SIZE);
        printf("Generated Key: ");
        print_hex(key, KEY_SIZE);
        printf("\n");
    }

    bool success = false;
    if (strcmp(mode, "encrypt") == 0) {
        // Validate JPG/PNG File - check if input file has image extension
        if (!is_valid_image_extension(input_file)) {
            printf("Error: Input file must be a JPG or PNG image\n");
            return 1;
        }
        // Encryption Flow
        success = encrypt_image(input_file, output_file, key);
    } else if (strcmp(mode, "decrypt") == 0) {
        // Decryption Flow
        success = decrypt_image(input_file, output_file, key);
    } else {
        printf("Error: Invalid mode. Use 'encrypt' or 'decrypt'\n");
        print_usage(argv[0]);
        return 1;
    }

    if (success) {
        printf("Operation completed successfully!\n");
    } else {
        printf("Operation failed.\n");
        return 1;
    }

    // Clean up OpenSSL
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}

bool is_valid_image_extension(const char *filename) {
    const char *extension = strrchr(filename, '.');
    if (extension == NULL) {
        return false;
    }
    
    extension++; // Skip the dot
    
    // Convert extension to lowercase for comparison
    char ext_lower[10] = {0}; // More than enough for file extensions
    int i = 0;
    while (extension[i] && i < 9) {
        ext_lower[i] = tolower(extension[i]);
        i++;
    }
    
    // Check if it's a supported image format
    return (strcmp(ext_lower, "jpg") == 0 || 
            strcmp(ext_lower, "jpeg") == 0 || 
            strcmp(ext_lower, "png") == 0);
}

void print_usage(const char *program_name) {
    printf("Usage: %s [encrypt|decrypt] [input_file] [output_file] [key(optional)]\n", program_name);
    printf("  - For encryption: input must be a JPG or PNG image\n");
    printf("  - For decryption: output should have .jpg or .png extension\n");
    printf("If no key is provided, a random one will be generated and displayed.\n");
    printf("Examples:\n");
    printf("  %s encrypt photo.jpg encrypted.bin\n", program_name);
    printf("  %s decrypt encrypted.bin recovered.jpg \"mysecretkey\"\n", program_name);
}

void generate_key(unsigned char *key, int size) {
    // Use secure random number generation if available
    if (RAND_bytes(key, size) != 1) {
        // Fallback to less secure method if OpenSSL random fails
        handle_openssl_error();
        srand(time(NULL));
        for (int i = 0; i < size; i++) {
            key[i] = rand() % 256;
        }
        printf("Warning: Using less secure random generation method\n");
    }
}

void print_hex(const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
}

ImageFormat detect_image_format(FILE *file) {
    long original_pos = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    unsigned char signature[8] = {0};
    size_t read_bytes = fread(signature, 1, 8, file);
    
    // Reset file position
    fseek(file, original_pos, SEEK_SET);
    
    if (read_bytes < 3) {
        return FORMAT_UNKNOWN;
    }
    
    // Check for JPEG signature (FF D8 FF)
    if (signature[0] == JPG_SIGNATURE[0] && 
        signature[1] == JPG_SIGNATURE[1] && 
        signature[2] == JPG_SIGNATURE[2]) {
        return FORMAT_JPG;
    }
    
    // Check for PNG signature (89 50 4E 47 0D 0A 1A 0A)
    if (read_bytes >= 8 &&
        signature[0] == PNG_SIGNATURE[0] && 
        signature[1] == PNG_SIGNATURE[1] &&
        signature[2] == PNG_SIGNATURE[2] &&
        signature[3] == PNG_SIGNATURE[3] &&
        signature[4] == PNG_SIGNATURE[4] &&
        signature[5] == PNG_SIGNATURE[5] &&
        signature[6] == PNG_SIGNATURE[6] &&
        signature[7] == PNG_SIGNATURE[7]) {
        return FORMAT_PNG;
    }
    
    return FORMAT_UNKNOWN;
}

void handle_openssl_error() {
    unsigned long err = ERR_get_error();
    if (err) {
        char err_msg[256];
        ERR_error_string_n(err, err_msg, sizeof(err_msg));
        printf("OpenSSL Error: %s\n", err_msg);
    }
}

// AES GCM mode encryption
int aes_gcm_encrypt(unsigned char *plaintext, int plaintext_len, 
                    const unsigned char *key, const unsigned char *iv, int iv_len,
                    unsigned char *ciphertext, unsigned char *tag) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    int ret;

    // Create and initialize the context
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        handle_openssl_error();
        return -1;
    }

    // Initialize the encryption operation
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        handle_openssl_error();
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Set IV length (default is 12 bytes)
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) {
        handle_openssl_error();
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Initialize key and IV
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
        handle_openssl_error();
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Encrypt plaintext
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        handle_openssl_error();
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;

    // Finalize encryption
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        handle_openssl_error();
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

    // Get the tag
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_SIZE, tag)) {
        handle_openssl_error();
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

// AES GCM mode decryption
int aes_gcm_decrypt(unsigned char *ciphertext, int ciphertext_len, 
                    const unsigned char *tag,
                    const unsigned char *key, const unsigned char *iv, int iv_len,
                    unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    // Create and initialize the context
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        handle_openssl_error();
        return -1;
    }

    // Initialize the decryption operation
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        handle_openssl_error();
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Set IV length
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) {
        handle_openssl_error();
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Initialize key and IV
    if(1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
        handle_openssl_error();
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Decrypt ciphertext
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        handle_openssl_error();
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    // Set expected tag value
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_SIZE, (void*)tag)) {
        handle_openssl_error();
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Finalize decryption
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0) {
        // If successful
        plaintext_len += len;
        return plaintext_len;
    } else {
        // If verification failed
        return -1;
    }
}

bool encrypt_image(const char *input_file, const char *output_file, const unsigned char *key) {
    FILE *fin = fopen(input_file, "rb");
    if (!fin) {
        printf("Error: Cannot open input file %s\n", input_file);
        return false;
    }
    
    // Verify it's a valid image file
    ImageFormat format = detect_image_format(fin);
    if (format == FORMAT_UNKNOWN) {
        printf("Error: The file %s is not a valid JPG or PNG image\n", input_file);
        fclose(fin);
        return false;
    }
    
    FILE *fout = fopen(output_file, "wb");
    if (!fout) {
        printf("Error: Cannot open output file %s\n", output_file);
        fclose(fin);
        return false;
    }

    // Write our encrypted file signature
    fwrite(ENCRYPTED_SIGNATURE, 1, SIGNATURE_SIZE, fout);
    
    // Store the original file format
    unsigned char format_byte = (format == FORMAT_JPG) ? 0x01 : 0x02;
    fwrite(&format_byte, 1, 1, fout);

    // Generate and write initialization vector (IV)
    unsigned char iv[IV_SIZE];
    generate_key(iv, IV_SIZE);
    fwrite(iv, 1, IV_SIZE, fout);
    
    printf("Image Format: %s\n", (format == FORMAT_JPG) ? "JPEG" : "PNG");
    printf("Encryption IV: ");
    print_hex(iv, IV_SIZE);
    printf("\n");

    // Read the entire file into memory
    fseek(fin, 0, SEEK_END);
    long file_size = ftell(fin);
    fseek(fin, 0, SEEK_SET);
    
    unsigned char *file_content = (unsigned char *)malloc(file_size);
    if (!file_content) {
        printf("Error: Memory allocation failed\n");
        fclose(fin);
        fclose(fout);
        return false;
    }
    
    if (fread(file_content, 1, file_size, fin) != file_size) {
        printf("Error: Could not read entire file\n");
        free(file_content);
        fclose(fin);
        fclose(fout);
        return false;
    }
    
    // Allocate memory for encrypted data
    unsigned char *encrypted_data = (unsigned char *)malloc(file_size + EVP_MAX_BLOCK_LENGTH);
    if (!encrypted_data) {
        printf("Error: Memory allocation failed\n");
        free(file_content);
        fclose(fin);
        fclose(fout);
        return false;
    }
    
    // Authentication tag
    unsigned char tag[GCM_TAG_SIZE];
    
    // Encrypt the data
    int encrypted_len = aes_gcm_encrypt(file_content, file_size, key, iv, IV_SIZE, 
                                        encrypted_data, tag);
    
    if (encrypted_len < 0) {
        printf("Error: Encryption failed\n");
        free(file_content);
        free(encrypted_data);
        fclose(fin);
        fclose(fout);
        return false;
    }
    
    // Write the GCM tag
    fwrite(tag, 1, GCM_TAG_SIZE, fout);
    
    // Write the encrypted data
    fwrite(encrypted_data, 1, encrypted_len, fout);
    
    printf("Encrypted %d bytes of image data\n", encrypted_len);
    printf("Authentication tag: ");
    print_hex(tag, GCM_TAG_SIZE);
    printf("\n");
    
    // Cleanup
    free(file_content);
    free(encrypted_data);
    fclose(fin);
    fclose(fout);
    return true;
}

bool decrypt_image(const char *input_file, const char *output_file, const unsigned char *key) {
    FILE *fin = fopen(input_file, "rb");
    if (!fin) {
        printf("Error: Cannot open input file %s\n", input_file);
        return false;
    }

    // Check for our encrypted file signature
    unsigned char file_signature[SIGNATURE_SIZE];
    if (fread(file_signature, 1, SIGNATURE_SIZE, fin) != SIGNATURE_SIZE) {
        printf("Error: File is too small or corrupted\n");
        fclose(fin);
        return false;
    }
    
    // Verify it's our encrypted format
    for (int i = 0; i < SIGNATURE_SIZE; i++) {
        if (file_signature[i] != ENCRYPTED_SIGNATURE[i]) {
            printf("Error: This is not a valid encrypted image file\n");
            fclose(fin);
            return false;
        }
    }
    
    // Read the image format
    unsigned char format_byte;
    if (fread(&format_byte, 1, 1, fin) != 1) {
        printf("Error: File format information is missing\n");
        fclose(fin);
        return false;
    }
    
    ImageFormat format;
    if (format_byte == 0x01) {
        format = FORMAT_JPG;
        printf("Detected original format: JPEG\n");
    } else if (format_byte == 0x02) {
        format = FORMAT_PNG;
        printf("Detected original format: PNG\n");
    } else {
        printf("Error: Unknown image format in encrypted file\n");
        fclose(fin);
        return false;
    }
    
    // Check and fix output file extension if needed
    char *new_output = NULL;
    const char *output_ext = strrchr(output_file, '.');
    bool need_extension = false;
    
    if (!output_ext) {
        need_extension = true;
    } else {
        // Convert extension to lowercase for comparison
        char ext_lower[10] = {0};
        int i = 0;
        output_ext++; // Skip the dot
        while (output_ext[i] && i < 9) {
            ext_lower[i] = tolower(output_ext[i]);
            i++;
        }
        
        // Check if extension matches the format
        if ((format == FORMAT_JPG && strcmp(ext_lower, "jpg") != 0 && strcmp(ext_lower, "jpeg") != 0) ||
            (format == FORMAT_PNG && strcmp(ext_lower, "png") != 0)) {
            need_extension = true;
        }
    }
    
    if (need_extension) {
        printf("Warning: Output file doesn't have the correct extension. Adding appropriate extension.\n");
        new_output = malloc(strlen(output_file) + 5); // +5 for .jpg/.png and null terminator
        if (!new_output) {
            printf("Error: Memory allocation failed\n");
            fclose(fin);
            return false;
        }
        strcpy(new_output, output_file);
        strcat(new_output, format == FORMAT_JPG ? ".jpg" : ".png");
        output_file = new_output;
    }

    FILE *fout = fopen(output_file, "wb");
    if (!fout) {
        printf("Error: Cannot open output file %s\n", output_file);
        if (new_output) free(new_output);
        fclose(fin);
        return false;
    }

    // Read initialization vector
    unsigned char iv[IV_SIZE];
    if (fread(iv, 1, IV_SIZE, fin) != IV_SIZE) {
        printf("Error: File format is invalid or file is corrupt\n");
        if (new_output) free(new_output);
        fclose(fin);
        fclose(fout);
        return false;
    }
    
    printf("Decryption IV: ");
    print_hex(iv, IV_SIZE);
    printf("\n");
    
    // Read the GCM tag
    unsigned char tag[GCM_TAG_SIZE];
    if (fread(tag, 1, GCM_TAG_SIZE, fin) != GCM_TAG_SIZE) {
        printf("Error: Authentication tag is missing\n");
        if (new_output) free(new_output);
        fclose(fin);
        fclose(fout);
        return false;
    }
    
    printf("Authentication tag: ");
    print_hex(tag, GCM_TAG_SIZE);
    printf("\n");
    
    // Read the encrypted data
    fseek(fin, 0, SEEK_END);
    long file_size = ftell(fin);
    // Subtract header size (signature + format byte + IV + tag)
    long data_size = file_size - SIGNATURE_SIZE - 1 - IV_SIZE - GCM_TAG_SIZE;
    
    if (data_size <= 0) {
        printf("Error: No encrypted data found\n");
        if (new_output) free(new_output);
        fclose(fin);
        fclose(fout);
        return false;
    }
    
    // Seek to the start of encrypted data
    fseek(fin, SIGNATURE_SIZE + 1 + IV_SIZE + GCM_TAG_SIZE, SEEK_SET);
    
    // Allocate memory for encrypted and decrypted data
    unsigned char *encrypted_data = (unsigned char *)malloc(data_size);
    unsigned char *decrypted_data = (unsigned char *)malloc(data_size);
    
    if (!encrypted_data || !decrypted_data) {
        printf("Error: Memory allocation failed\n");
        if (encrypted_data) free(encrypted_data);
        if (decrypted_data) free(decrypted_data);
        if (new_output) free(new_output);
        fclose(fin);
        fclose(fout);
        return false;
    }
    
    if (fread(encrypted_data, 1, data_size, fin) != data_size) {
        printf("Error: Could not read encrypted data\n");
        free(encrypted_data);
        free(decrypted_data);
        if (new_output) free(new_output);
        fclose(fin);
        fclose(fout);
        return false;
    }
    
    int decrypted_len = aes_gcm_decrypt(encrypted_data, data_size, tag, key, iv, IV_SIZE, decrypted_data);
    
    if (decrypted_len < 0) {
        printf("Error: Decryption failed. The file might be corrupted or the key is incorrect.\n");
        free(encrypted_data);
        free(decrypted_data);
        if (new_output) free(new_output);
        fclose(fin);
        fclose(fout);
        return false;
    }
    
    fwrite(decrypted_data, 1, decrypted_len, fout);
    
    printf("Decrypted %d bytes to %s image\n", decrypted_len, 
           format == FORMAT_JPG ? "JPEG" : "PNG");
    
    free(encrypted_data);
    free(decrypted_data);
    if (new_output) free(new_output);
    fclose(fin);
    fclose(fout);
    return true;
}