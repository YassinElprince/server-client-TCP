#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#define PORT 8080
#define BUFFER_SIZE 1024
unsigned char KEY[16] = "0123456789abcdef";
unsigned char IV[16]  = "abcdef9876543210";

int authenticate(char *user, char *pass) {
    FILE *file = fopen("users.txt", "r");
    char file_user[50];
    char file_hash[65];
    if (!file) return 0;
    pass[strcspn(pass, "\r\n")] = 0;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    char hash_str[65];
    SHA256((unsigned char *)pass, strlen(pass), hash);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hash_str + (i * 2), "%02x", hash[i]);}
    hash_str[64] = '\0';
    while (fscanf(file, "%s %s", file_user, file_hash) != EOF) {
        if (strcmp(user, file_user) == 0 &&
            strcmp(hash_str, file_hash) == 0) {
            fclose(file);
            return 1;}}
    fclose(file);
    return 0;}

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
    void *handle_client(void *socket_desc) {
    int sock = *(int *)socket_desc;
    free(socket_desc);
    printf("Client connected\n");
    char buffer[BUFFER_SIZE];
    memset(buffer, 0, BUFFER_SIZE);
    int n = read(sock, buffer, BUFFER_SIZE);
    if (n <= 0) {
        close(sock);
        return NULL;}
    buffer[n] = '\0';
    char username[50], password[50];
    sscanf(buffer, "%s %s", username, password);
    if (!authenticate(username, password)) {
        send(sock, "AUTH_FAILED", 11, 0);
        close(sock);
        return NULL;}
    send(sock, "AUTH_SUCCESS", 12, 0);
    printf("Authenticated: %s\n", username);
    while (1) {
        unsigned char enc_buf[BUFFER_SIZE];
        unsigned char dec_buf[BUFFER_SIZE];
        int len_net;
        int r = read(sock, &len_net, sizeof(len_net));
        if (r <= 0) break;
        int enc_len = ntohl(len_net);
        int total = 0;
        while (total < enc_len) {
            int bytes = read(sock, enc_buf + total, enc_len - total);
            if (bytes <= 0) break;
            total += bytes;}
        if (total <= 0) break;
        int dec_len = decrypt(enc_buf, enc_len, dec_buf);
        dec_buf[dec_len] = '\0';
        printf("Client: %s\n", dec_buf);
        char *reply = "Message received";
        int reply_len = encrypt((unsigned char *)reply, strlen(reply), enc_buf);
        int reply_net = htonl(reply_len);
        send(sock, &reply_net, sizeof(reply_net), 0);
        send(sock, enc_buf, reply_len, 0);}
    close(sock);
    return NULL;}

int main() {
    int server_fd;
    struct sockaddr_in address;
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    bind(server_fd, (struct sockaddr *)&address, sizeof(address));
    listen(server_fd, 10);
    printf("Server listening on port 8080...\n");
    while (1) {
        int addrlen = sizeof(address);
        int *new_socket = malloc(sizeof(int));
        *new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen);
        pthread_t thread_id;
        pthread_create(&thread_id, NULL, handle_client, (void *)new_socket);
        pthread_detach(thread_id);}
    return 0;}
