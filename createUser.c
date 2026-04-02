#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>

int main() {
    char username[256];
    char password[256];
    unsigned char hash[SHA256_DIGEST_LENGTH];
    printf("Enter username: ");
    scanf("%255s", username);
    printf("Enter password: ");
    scanf("%255s", password);
    password[strcspn(password, "\r\n")] = 0;
    SHA256((unsigned char *)password, strlen(password), hash);