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
    FILE *fp = fopen("users.txt", "a");
    fprintf(fp, "%s ", username);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        fprintf(fp, "%02x", hash[i]);}
    fprintf(fp, "\n");
    fclose(fp);
    printf("User added successfully.\n");
    return 0;}
