#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/evp.h>
#define PORT 8080
#define BUFFER_SIZE 1024
unsigned char KEY[16] = "0123456789abcdef";
unsigned char IV[16]  = "abcdef9876543210";

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, KEY, IV);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, plaintext_len;
    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, KEY, IV);
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;
    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;}

int main() {
    int sock;
    struct sockaddr_in serv_addr;
    sock = socket(AF_INET, SOCK_STREAM, 0);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection Failed");
        return -1;}
    printf("Connected to server\n");
    char username[50], password[50];
    printf("Username: ");
    scanf("%s", username);
    printf("Password: ");
    scanf("%s", password);
    char creds[100];
    sprintf(creds, "%s %s", username, password);
    send(sock, creds, strlen(creds), 0);
    char buffer[BUFFER_SIZE];
    int n = read(sock, buffer, BUFFER_SIZE);
    buffer[n] = '\0';
    if (strcmp(buffer, "AUTH_SUCCESS") != 0) {
        printf("Authentication Failed\n");
        return 0;}
    printf("Authenticated!\n");
    getchar();
    while (1) {
        char message[BUFFER_SIZE];
        unsigned char enc_buf[BUFFER_SIZE];
        unsigned char dec_buf[BUFFER_SIZE];
        printf("Enter message: ");
        fgets(message, BUFFER_SIZE, stdin);
        message[strcspn(message, "\n")] = 0;
        if (strcmp(message, "exit") == 0)
            break;
        int enc_len = encrypt((unsigned char *)message, strlen(message), enc_buf);
        int len_net = htonl(enc_len);
        send(sock, &len_net, sizeof(len_net), 0);
        send(sock, enc_buf, enc_len, 0);
        int reply_net;
        read(sock, &reply_net, sizeof(reply_net));
        int reply_len = ntohl(reply_net);
        int total = 0;
        while (total < reply_len) {
            int bytes = read(sock, enc_buf + total, reply_len - total);
            if (bytes <= 0) break;
            total += bytes;}
        int dec_len = decrypt(enc_buf, reply_len, dec_buf);
        dec_buf[dec_len] = '\0';
        printf("Server: %s\n", dec_buf);}
    close(sock);
    return 0;}
