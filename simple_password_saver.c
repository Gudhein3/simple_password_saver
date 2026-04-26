#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#define SHA1_IMPLEMENTATION
#include "third_party/sha1.h"
#include "third_party/aes.h"
#include <termios.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>

#ifndef AES128
#error "Bad AES library"
#endif
static_assert(AES_BLOCKLEN == 16, "Bad AES library");
static_assert(SHA1_DIGEST_BYTE_LENGTH == 20, "Bad SHA1 library");
#define MAX_PASSWORD_LENGTH 512

// Home-relative; basically "~"$PASSWORDS_DIRECTORY
#define PASSWORDS_DIRECTORY "passwords"

/*
TODOs:
    Add local home storage so it will be easier to add/set/get passwords.
*/

typedef struct { // AES Encrypted
    uint8_t hash[20];   // SHA1 hash of the data.
    uint64_t size;      // Excluding panding
    uint64_t file_size; // Including panding
    uint8_t data[];
} __attribute__((packed)) Secret;

void encrypt(const char *key, uint8_t *data, size_t size) {
    assert(size % AES_BLOCKLEN == 0 && "Size of data should be divisible by 16");
    size_t key_length = strlen(key);
    uint8_t key_hash[SHA1_DIGEST_BYTE_LENGTH];
    sha1_digest((uint8_t *)key, key_length, key_hash);

    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key_hash+2, key_hash);
    AES_CBC_encrypt_buffer(&ctx, data, size);
}

void decrypt(const char *key, uint8_t *data, size_t size) {
    assert(size % AES_BLOCKLEN == 0 && "Size of data should be divisible by 16");
    size_t key_length = strlen(key);
    uint8_t key_hash[SHA1_DIGEST_BYTE_LENGTH];
    sha1_digest((uint8_t *)key, key_length, key_hash);

    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key_hash+2, key_hash);
    AES_CBC_decrypt_buffer(&ctx, data, size);
}

void usage(const char *program_name) {
    fprintf(stderr, "Usage: %s ACTION secret's-name\n"
                    "\tactions:\n"
                    "\t  decrypt - Decrypt the secret\n"
                    "\t  encrypt - Encrypt the secret\n"
                    "\t  remove - Remove the secret\n"
                    "\t  list   - List all saved secrets\n", program_name);
}

char current_directory[4096]; // 4096 characters in an absolute path should be enough for everybody.

int main(int argc, char **argv) {
    if (argc < 2) {
        usage(argv[0]);
        return 2;
    }

    char *homedir = getenv("HOME");
    if (!homedir) {
        fprintf(stderr, "Required environment variable \"$HOME\" is not defined\n");
        return 1;
    }

    if (chdir(homedir) < 0) {
        fprintf(stderr, "Failed chdir to home directory: %s\n", strerror(errno));
        return 1;
    }

    if (chdir(PASSWORDS_DIRECTORY) < 0) {
        if (errno == ENOENT) { // Maybe we should firstly make the passwords directory.
            if (mkdir(PASSWORDS_DIRECTORY, S_IRWXU) < 0) { // rwx------
                fprintf(stderr, "Failed mkdir the passwords directory: %s\n", strerror(errno));
                return 1;
            }
            if (chdir(PASSWORDS_DIRECTORY) >= 0) {
                goto no_problemo; // We just had to mkdir the directory.
            }
        }
        fprintf(stderr, "Failed chdir to the passwords directory: %s\n", strerror(errno));
        return 1;
        no_problemo:;
    } // We are now in the passwords directory.

    struct stat stat_buf;
    if (stat(".", &stat_buf) < 0) {
        fprintf(stderr, "Failed stat to the passwords directory: %s\n", strerror(errno));
        return 1;
    }
    if ((stat_buf.st_mode & (S_IRWXG|S_IRWXO)) != 0) {
        fprintf(stderr, "Too open permissions for the passwords directory, required rwx------\n");
        return 1;
    }
    if ((stat_buf.st_mode & S_IRWXU) != S_IRWXU) {
        fprintf(stderr, "Too close permissions for the passwords directory, required rwx------\n");
        return 1;
    }

    enum {
        Decrypt,
        Encrypt,
        Remove
    } action;
    if (strcmp(argv[1], "encrypt") == 0) {
        if (argc != 3) {
            usage(argv[0]);
            fprintf(stderr, "Expected secret's name\n");
            return 2;
        }
        action = Encrypt;
    }
    else if (strcmp(argv[1], "decrypt") == 0) {
        if (argc != 3) {
            usage(argv[0]);
            fprintf(stderr, "Expected secret's name\n");
            return 2;
        }
        action = Decrypt;
    }
    else if (strcmp(argv[1], "remove") == 0) {
        if (argc != 3) {
            usage(argv[0]);
            fprintf(stderr, "Expected secret's name\n");
            return 2;
        }
        action = Remove;
    }
    else if (strcmp(argv[1], "list") == 0) {
        DIR *dir = opendir(".");
        if (!dir) {
            fprintf(stderr, "Failed to open the passwords directory: %s\n", strerror(errno));
            return 2;
        }
        struct dirent *dirent;
        while ((dirent = readdir(dir))) {
            if (dirent->d_name[0] != '.')
                printf(". %s\n", dirent->d_name);
        }
        return 0;
    }
    else {
        usage(argv[0]);
        fprintf(stderr, "Unknown action: %s\n", argv[1]);
        return 2;
    }

    // Modifying argv might look illegal, but it is in our memory, so everything is legal.
    for (char *it = argv[2]; *it; ++it) {
        if (*it == '/') {
            *it = '\\';
        }
        else if (*it == '.') { // https:\\www!example!com\login
            *it = '!';
        }
    }

    if (action == Remove) {
        fprintf(stderr, "Do You REALLY WANT to REMOVE THE SECRET? Type 49406 if so\n");

        char buf[5] = {0};
        fread(buf, 1, 6, stdin);
        if (memcmp(buf, "49406\n", 5) != 0) {
            fprintf(stderr, "Aborted\n");
            return 1;
        }

        if (unlink(argv[2]) < 0) {
            fprintf(stderr, "Failed to unlink(remove) file: %s: %s\n", argv[2], strerror(errno));
            return 2;
        }
        return 0;
    }

    char password[MAX_PASSWORD_LENGTH+1];
    struct termios term;
    tcgetattr(STDIN_FILENO, &term);
    int original_term_c_lflag = term.c_lflag;
    term.c_lflag &= ~(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &term);
    fprintf(stderr, "Please, enter your master password\n");
    {
        int i;
        for (i = 0;; ++i) { // Consuming all pending characters, so user wouldn't accidentally show them
            char ch = getchar();
            if (i < MAX_PASSWORD_LENGTH) {
                password[i] = ch;
            }
            if (ch == '\n' || ch == EOF) break;
        }
        password[i] = 0;
    }

    term.c_lflag = original_term_c_lflag;
    tcsetattr(STDIN_FILENO, TCSANOW, &term);

    if (action == Encrypt) {

        FILE *output_file = fopen(argv[2], "rb");
        if (output_file) {
            fclose(output_file);
            fprintf(stderr, "Wait, the secret is already listed, do you want to rewrite it? Type 2026 if so\n");
            char buf[5] = {0};
            fread(buf, 1, 5, stdin);
            if (memcmp(buf, "2026\n", 5) != 0) {
                fprintf(stderr, "Aborted\n");
                return 1;
            }
        }
        output_file = fopen(argv[2], "wb");
        if (!output_file) {
            fprintf(stderr, "Failed to open file: %s: %s\n", argv[2], strerror(errno));
            return 2;
        }

        const size_t block_size = 1024;
        size_t capacity = block_size;
        size_t count = 0;
        uint8_t *data = malloc(capacity);
        if (!data) {
            fprintf(stderr, "Failed to alloc memory: %s\n", strerror(errno));
            return 1;
        }
        fprintf(stderr, "Enter secret you want to save(press ^D to finish)\n");
        term.c_lflag &= ~(ECHO);
        tcsetattr(STDIN_FILENO, TCSANOW, &term);
        for (;;) {
            ssize_t size = fread(data+count, 1, block_size, stdin); // Shouldn't fail
            count += size;
            if (count >= capacity) {
                capacity *= 2;
                data = realloc(data, capacity);
                if (!data) {
                    term.c_lflag = original_term_c_lflag;
                    tcsetattr(STDIN_FILENO, TCSANOW, &term);
                    fprintf(stderr, "Failed to alloc memory: %s\n", strerror(errno));
                    return 1;
                }
            }
            else if (size == 0) {
                break; // We probably read everything.
            }
        }
        term.c_lflag = original_term_c_lflag;
        tcsetattr(STDIN_FILENO, TCSANOW, &term);

        size_t count_aligned = count+16-(count&15);
        Secret *secret = malloc(sizeof(Secret)+count_aligned);
        memcpy(secret->data, data, count);
        memset(secret->data+count, 69, count_aligned-count); // TODO: Maybe fill padding with random bytes.
        sha1_digest(secret->data, count, secret->hash);
        secret->size = count;
        secret->file_size = count_aligned;

        encrypt(password, secret->data, secret->file_size);
        fwrite(secret, 1, sizeof(Secret)+count_aligned, output_file);
    }
    else if (action == Decrypt) {
        FILE *input_file = fopen(argv[2], "rb");
        if (!input_file) {
            fprintf(stderr, "Failed to open file: %s: %s\n", argv[2], strerror(errno));
            return 2;
        }

        fseek(input_file, 0, SEEK_END);
        size_t input_size = ftell(input_file);
        fseek(input_file, 0, SEEK_SET);
        Secret *secret = malloc(input_size);
        fread(secret, 1, input_size, input_file);

        decrypt(password, secret->data, secret->file_size);
        uint8_t hash[20];
        sha1_digest(secret->data, secret->size, hash);
        if (memcmp(secret->hash, hash, 20) != 0) {
            fprintf(stderr, "Invalid password\n");
            return 1;
        }
        fwrite(secret->data, 1, secret->size, stdout);
    }
    else {
        assert(0 && "Unreachable");
    }
    // Opened file descriptors will be automatically closed by the operating system
    return 0;
}
