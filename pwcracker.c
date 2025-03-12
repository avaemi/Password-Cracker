#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <openssl/sha.h>

const int SHA_LENGTH = 32;

uint8_t hex_to_byte(unsigned char h1, unsigned char h2) {
    uint8_t byte = 0;
    if (h1 >= '0' && h1 <= '9') byte += (h1 - '0') << 4;
    if (h1 >= 'a' && h1 <= 'f') byte += (h1 - 'a' + 10) << 4;
    if (h2 >= '0' && h2 <= '9') byte += h2 - '0';
    if (h2 >= 'a' && h2 <= 'f') byte += h2 - 'a' + 10;
    return byte;
}

void hexstr_to_hash(char hexstr[], unsigned char hash[32]) {
    for (int i = 0; i < 32; i++) {
        hash[i] = hex_to_byte(hexstr[2 * i], hexstr[2 * i + 1]);
    }
}

int8_t check_password(char password[], unsigned char given_hash[32]) {
    unsigned char hash[SHA_LENGTH];
    SHA256((unsigned char*)password, strlen(password), hash);
    
    if (memcmp(hash, given_hash, SHA_LENGTH) == 0) {
        printf("Found password: SHA256(%s) = ", password);
        for (int i = 0; i < SHA_LENGTH; i++) {
            printf("%02x", hash[i]);
        }
        printf("\n");
        return 1;
    }
    return 0;
}

int8_t crack_password(char password[], unsigned char given_hash[]) {
    char temp_password[256];
    strcpy(temp_password, password);

    if (check_password(temp_password, given_hash)) return 1;

    for (int i = 0; i < strlen(password); i++) {
        if (temp_password[i] >= 'a' && temp_password[i] <= 'z') {
            temp_password[i] -= 32;
            if (check_password(temp_password, given_hash)) {
                strcpy(password, temp_password);
                return 1;
            }
            temp_password[i] += 32;
        } else if (temp_password[i] >= 'A' && temp_password[i] <= 'Z') {
            temp_password[i] += 32;
            if (check_password(temp_password, given_hash)) {
                strcpy(password, temp_password);
                return 1;
            }
            temp_password[i] -= 32;
        }
    }

    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <SHA256 hash>\n", argv[0]);
        return 1;
    }

    unsigned char given_hash[32];
    hexstr_to_hash(argv[1], given_hash);

    char password[256];

    // Removed prompt for cleaner output in automated test
    // printf("Enter potential passwords (Ctrl-D to end input):\n");

    while (fgets(password, sizeof(password), stdin) != NULL) {
        password[strcspn(password, "\n")] = '\0';
        if (crack_password(password, given_hash)) {
            return 0;
        }
    }

    printf("Did not find a matching password\n");
    return 0;
}