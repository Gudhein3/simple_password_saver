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
#include <time.h>

#define CURRENT_PATCH 0

#ifndef AES128
#error "Bad AES library"
#endif
static_assert(AES_BLOCKLEN == 16, "Bad AES library");
static_assert(SHA1_DIGEST_BYTE_LENGTH == 20, "Bad SHA1 library");
#define MAX_PASSWORD_LENGTH 512

// Home directory-relative
#define PASSWORDS_DIRECTORY "passwords"

#define malloc_check(ptr) do {fall_iff((ptr) != NULL, "Buy more RAM lol");} while(0)

typedef struct {
    uint8_t patch;      // Lastest patch applied
    uint64_t size;      // Excluding panding
    uint64_t file_size; // Including panding
    uint8_t data[];
} __attribute__((packed)) Secret;

// Obsolete
typedef struct {
    uint8_t hash[20];   // Security risk
    uint64_t size;      // Excluding panding
    uint64_t file_size; // Including panding
    uint8_t data[];
} __attribute__((packed)) Secret0;

void fall_iff(int cond, const char *message) {
    if (!cond) {
        fprintf(stderr, message);
        abort();
    }
}

struct termios term;
int original_term_c_lflag;

void get_lepasswd_base(char password[MAX_PASSWORD_LENGTH+1]) {
    term.c_lflag &= ~(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &term);
    {
        int i;
        for (i = 0;; ++i) {
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
}

void get_lepasswd(char password[MAX_PASSWORD_LENGTH+1], const char *prompt) {
    char password_rep[MAX_PASSWORD_LENGTH+1];
    fprintf(stderr, "%s", prompt);
    get_lepasswd_base(password);
    fprintf(stderr, "Please repeat again\n");
    get_lepasswd_base(password_rep);
    if (strcmp(password, password_rep) != 0) {
        fprintf(stderr, "Sorry, passwords don't match\n");
        exit(1);
    }
    memset(password_rep, 0, sizeof(password_rep));
}

// I haven't found any libc-native solutions.
void readline(size_t size;
              char buffer[size], size_t size) {
    size_t i;
    for (i = 0; i < size-1; ++i) {
        char c;
        if (fread(&c, 1, 1, stdin) == 0) break;
        if (c == '\n' || c == '\r') break;
        buffer[i] = c;
    }
    buffer[i] = 0;
}

int are_you_sure(const char *prompt) {
    srand(time(NULL)); // Not meant to be cryptographically secure.
    int x = rand()%10000;
    fprintf(stderr, "%s Type %d and press enter if so\n", prompt, x);
    char buf[7/*To make sure it 100% won't overfill*/] = {0};
    char buf2[7] = {0};
    snprintf(buf, 6, "%d", x);
    readline(buf2, sizeof(buf2));
    return strcmp(buf, buf2) == 0;
}

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
    fprintf(stderr, "Usage: %s ACTION\n"
                    "\tactions:\n"
                    "\t  decrypt name   - Decrypt a secret\n"
                    "\t  encrypt name   - Encrypt a secret\n"
                    "\t  recrypt name   - Reëncrypt a secret\n"
                    "\t  fix     name   - Fix a secret\n"
                    "\t  fix0    name   - Fix a secret using the #0 patch\n"
                    "\t  remove  name   - Remove a secret\n"
                    "\t  list           - List all saved secrets\n", program_name);
}

char current_directory[4096]; // 4096 characters in an absolute path should be enough for everybody.

void verify_secret(Secret *secret) {
    if (secret->patch > CURRENT_PATCH) {
        fprintf(stderr, "Aborted: the file has #%d patch, while the manager supports only #%d\n", secret->patch, CURRENT_PATCH);
        exit(1);
    }

    int corruption_level = (secret->file_size != secret->size+16-(secret->size&15)<<0);

    if (corruption_level != 0) {
        fprintf(stderr, "Sorry, your secret file seems to be corrupted with corruption code 0o%o.\n"
                        "Perhaps you suddenly overwrote the file,\n"
                        "Or you forgot to apply some patches :)", corruption_level);
        exit(1);
    }

    for (size_t i = secret->size; i < secret->file_size; ++i) {
        if (secret->data[i] != 69) {
            fprintf(stderr, "Secret cannot be decrypted. It may be caused by file corruption or entering an incorrect password\n");
            exit(1);
        }
    }
}

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
        Recrypt,
        Remove,
        Fix,
        Fix0
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
    else if (strcmp(argv[1], "recrypt") == 0) {
        if (argc != 3) {
            usage(argv[0]);
            fprintf(stderr, "Expected secret's name\n");
            return 2;
        }
        action = Recrypt;
    }
    else if (strcmp(argv[1], "remove") == 0) {
        if (argc != 3) {
            usage(argv[0]);
            fprintf(stderr, "Expected secret's name\n");
            return 2;
        }
        action = Remove;
    }
    else if (strcmp(argv[1], "fix") == 0) {
        if (argc != 3) {
            usage(argv[0]);
            fprintf(stderr, "Expected secret's name\n");
            return 2;
        }
        action = Fix;
    }
    else if (strcmp(argv[1], "fix0") == 0) {
        if (argc != 3) {
            usage(argv[0]);
            fprintf(stderr, "Expected secret's name\n");
            return 2;
        }
        action = Fix0;
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

    // Modifying argv might look illegal, but it is in our memory, so everything is nice :)
    for (char *it = argv[2]; *it; ++it) {
        if (*it == '/') {
            *it = '\\';
        }
        else if (*it == '.') { // https:\\www!example!com\login
            *it = '!';
        }
    }

    if (action == Remove) {
        if (!are_you_sure("Do you really want to REMOVE the secret?")) {
            fprintf(stderr, "Aborted\n");
            return 1;
        }

        if (unlink(argv[2]) < 0) {
            fprintf(stderr, "Failed to unlink(remove) file: %s: %s\n", argv[2], strerror(errno));
            return 2;
        }
        return 0;
    }
    else if (action == Fix0) {
        if (!are_you_sure("Are you sure this password should be fixed using the #0 patch? You cannot undo the action.")) {
            fprintf(stderr, "Aborted\n");
            return 1;
        }
        FILE *the_file = fopen(argv[2], "rb");
        if (!the_file) {
            fprintf(stderr, "Failed to open file: %s: %s\n", argv[2], strerror(errno));
            return 2;
        }

        fseek(the_file, 0, SEEK_END); // Evil offset hack. Don't touch it unless you know what you're about to do.
        size_t the_size = ftell(the_file);
        fall_iff(the_size > 19, "wtf?");
        the_size -= 19;
        fseek(the_file, 19, SEEK_SET);
        Secret *secret = malloc(the_size);
        malloc_check(secret);
        fread(secret, 1, the_size, the_file);
        secret->patch = 0;

        fclose(the_file);
        the_file = fopen(argv[2], "wb"); // Purely for truncation purposes(TBD: I don't know how to spell it properly and I don't have internet to check)
        if (!the_file) {
            fprintf(stderr, "Failed to open file: %s: %s\n", argv[2], strerror(errno));
            return 2;
        }
        fwrite(secret, 1, the_size, the_file);

        return 0;
    }
    else if (action == Fix) {
        FILE *the_file = fopen(argv[2], "rb");
        if (!the_file) {
            fprintf(stderr, "Failed to open file: %s: %s\n", argv[2], strerror(errno));
            return 2;
        }

        fseek(the_file, 0, SEEK_END); // Evil offset hack. Don't touch it unless you know what you're about to do.
        size_t the_size = ftell(the_file);
        fall_iff(the_size > 19, "wtf?");
        the_size -= 19;
        fseek(the_file, 19, SEEK_SET);
        Secret *secret = malloc(the_size);
        malloc_check(secret);
        fread(secret, 1, the_size, the_file);

        if (secret->patch == CURRENT_PATCH) {
            fprintf(stderr, "Aborted: already patched on #%d\n", CURRENT_PATCH);
            return 1;
        }
        else if (secret->patch > CURRENT_PATCH) {
            fprintf(stderr, "Aborted: the file has #%d patch, while the manager supports only #%d\n", secret->patch, CURRENT_PATCH);
            return 1;
        }

        if (!are_you_sure("Are you sure this password should be fixed using the #0 patch? You cannot undo the action.")) {
            fprintf(stderr, "Aborted\n");
            return 1;
        }

        fclose(the_file);
        the_file = fopen(argv[2], "wb"); // Purely for truncation purposes(TBD: I don't know how to spell it properly and I don't have internet to check)
        if (!the_file) {
            fprintf(stderr, "Failed to open file: %s: %s\n", argv[2], strerror(errno));
            return 2;
        }
        fwrite(secret, 1, the_size, the_file);

        return 0;
    }
    tcgetattr(STDIN_FILENO, &term);
    original_term_c_lflag = term.c_lflag;


    if (action == Encrypt) {
        char password[MAX_PASSWORD_LENGTH+1];
        get_lepasswd(password, "Please, enter your master password\n");
        FILE *output_file = fopen(argv[2], "rb");
        if (output_file) {
            fclose(output_file);
            if (!are_you_sure("Wait, the secret is already listed, do you want to rewrite it?")) {
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
        malloc_check(data);
        if (!data) {
            fprintf(stderr, "Failed to alloc memory: %s\n", strerror(errno));
            return 1;
        }
        fprintf(stderr, "Enter secret you want to save(press ^D^D to finish)\n"); // XXXXX: Why do we need to press ^D twice??!
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
                break; // We've probably done reading everything.
            }
        }
        term.c_lflag = original_term_c_lflag;
        tcsetattr(STDIN_FILENO, TCSANOW, &term);

        size_t count_aligned = count+16-(count&15);
        Secret *secret = malloc(sizeof(Secret)+count_aligned);
        malloc_check(secret);
        secret->patch = 0;
        memcpy(secret->data, data, count);
        memset(secret->data+count, 69, count_aligned-count); // Password validation code.
        secret->size = count;
        secret->file_size = count_aligned;

        encrypt(password, secret->data, secret->file_size);
        fwrite(secret, 1, sizeof(Secret)+count_aligned, output_file);
    }
    else if (action == Decrypt) {
        char password[MAX_PASSWORD_LENGTH+1];
        fprintf(stderr, "Please, enter your master password\n");
        get_lepasswd_base(password);
        FILE *input_file = fopen(argv[2], "rb");
        if (!input_file) {
            fprintf(stderr, "Failed to open file: %s: %s\n", argv[2], strerror(errno));
            return 2;
        }

        fseek(input_file, 0, SEEK_END);
        size_t input_size = ftell(input_file);
        fseek(input_file, 0, SEEK_SET);
        Secret *secret = malloc(input_size);
        malloc_check(secret);
        fread(secret, 1, input_size, input_file);
        decrypt(password, secret->data, secret->file_size);
        verify_secret(secret);

        uint8_t hash[20];
        fwrite(secret->data, 1, secret->size, stdout);
    }
    else if (action == Recrypt) {
        char password[MAX_PASSWORD_LENGTH+1];
        fprintf(stderr, "Please, enter your old master password\n");
        get_lepasswd_base(password);
        FILE *the_file = fopen(argv[2], "r+b");
        if (!the_file) {
            fprintf(stderr, "Failed to open file: %s: %s\n", argv[2], strerror(errno));
            return 2;
        }

        fseek(the_file, 0, SEEK_END);
        size_t the_size = ftell(the_file);
        fseek(the_file, 0, SEEK_SET);
        Secret *secret = malloc(the_size);
        malloc_check(secret);
        fread(secret, 1, the_size, the_file);

        decrypt(password, secret->data, secret->file_size);
        verify_secret(secret);

        fprintf(stderr, "Please, enter your new master password\n");
        get_lepasswd_base(password);
        encrypt(password, secret->data, secret->file_size);
        fseek(the_file, 0, SEEK_SET);
        fwrite(secret, 1, the_size, the_file);
    }
    else {
        assert(0 && "Unreachable");
    }
    // Opened file descriptors will be automatically closed by the operating system
    return 0;
}
