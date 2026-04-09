#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>

int main() {
    char username[256];
    char password[256];
    unsigned char hash[SHA256_DIGEST_LENGTH];
    int level;                         
    printf("Enter username: ");
    scanf("%255s", username);
    printf("Enter password: ");
    scanf("%255s", password);
    password[strcspn(password, "\r\n")] = 0;
    printf("Enter access level (1=Entry, 2=Medium, 3=Top): ");
    scanf("%d", &level);
    if (level < 1 || level > 3) {
        printf("Invalid level. Must be 1, 2, or 3.\n");
        return 1;}
    SHA256((unsigned char *)password, strlen(password), hash);
    FILE *fp = fopen("users.txt", "a");
    fprintf(fp, "%s ", username);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        fprintf(fp, "%02x", hash[i]);}
    fprintf(fp, " %d\n", level);     
    fclose(fp);
    printf("User added successfully.\n");
    return 0;}
