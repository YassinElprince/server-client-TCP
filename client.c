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
    char username[50], password[50], creds[110];
    printf("Username: ");
    scanf("%s", username);
    printf("Password: ");
    scanf("%s", password);
    sprintf(creds, "%s %s", username, password);
    send(sock, creds, strlen(creds), 0);
    char buffer[BUFFER_SIZE];
    int n = read(sock, buffer, BUFFER_SIZE - 1);
    if (n <= 0) { close(sock); return -1; }
    buffer[n] = '\0';
    if (strncmp(buffer, "AUTH_SUCCESS", 12) != 0) {
        printf("Authentication Failed\n");
        close(sock);
        return 0;}
    int level = 0;
    sscanf(buffer, "AUTH_SUCCESS %d", &level);
    printf("Authenticated!\n");
    if      (level == 1) printf("Access Level: 1\n");
    else if (level == 2) printf("Access Level: 2\n");
    else if (level == 3) printf("Access Level: 3\n");
    getchar(); 
    while (1) {
        char message[BUFFER_SIZE];
        unsigned char enc_buf[BUFFER_SIZE * 4];
        unsigned char dec_buf[BUFFER_SIZE * 4];
        int len_net, enc_len, total, bytes;
        printf("Enter command: ");
        fgets(message, BUFFER_SIZE, stdin);
        message[strcspn(message, "\n")] = 0;
        if (strlen(message) == 0) continue;
        if (strcmp(message, "exit") == 0) break;
        if (strncmp(message, "upload ", 7) == 0) {
            char filename[256];
            sscanf(message + 7, "%255s", filename);
            enc_len = encrypt((unsigned char *)message, strlen(message), enc_buf);
            len_net = htonl(enc_len);
            send(sock, &len_net, sizeof(len_net), 0);
            send(sock, enc_buf, enc_len, 0);
            int resp_net;
            read(sock, &resp_net, sizeof(resp_net));
            int resp_enc_len = ntohl(resp_net);
            total = 0;
            while (total < resp_enc_len) {
                bytes = read(sock, enc_buf + total, resp_enc_len - total);
                if (bytes <= 0) break;
                total += bytes;}
            int resp_dec_len = decrypt(enc_buf, resp_enc_len, dec_buf);
            dec_buf[resp_dec_len] = '\0';
            if (strcmp((char *)dec_buf, "READY") != 0) {
                printf("Server: %s\n", (char *)dec_buf);
                continue;}
            FILE *fp = fopen(filename, "rb");
            if (!fp) {
                printf("Error: local file '%s' not found.\n", filename);
                char zero[] = "0";
                int z_enc = encrypt((unsigned char *)zero, strlen(zero), enc_buf);
                int z_net = htonl(z_enc);
                send(sock, &z_net, sizeof(z_net), 0);
                send(sock, enc_buf, z_enc, 0);
                continue;}
            fseek(fp, 0, SEEK_END);
            int filesize = (int)ftell(fp);
            rewind(fp);
            char size_str[32];
            sprintf(size_str, "%d", filesize);
            int sz_enc_len = encrypt((unsigned char *)size_str, strlen(size_str), enc_buf);
            int sz_net = htonl(sz_enc_len);
            send(sock, &sz_net, sizeof(sz_net), 0);
            send(sock, enc_buf, sz_enc_len, 0);
            unsigned char *file_buf = malloc(filesize);
            unsigned char *file_enc = malloc(filesize + 64);
            fread(file_buf, 1, filesize, fp);
            fclose(fp);
            int fd_enc_len = encrypt(file_buf, filesize, file_enc);
            int fd_net = htonl(fd_enc_len);
            send(sock, &fd_net, sizeof(fd_net), 0);
            send(sock, file_enc, fd_enc_len, 0);
            free(file_buf);
            free(file_enc);
            int conf_net;
            read(sock, &conf_net, sizeof(conf_net));
            int conf_enc_len = ntohl(conf_net);
            total = 0;
            while (total < conf_enc_len) {
                bytes = read(sock, enc_buf + total, conf_enc_len - total);
                if (bytes <= 0) break;
                total += bytes;}
            int conf_dec_len = decrypt(enc_buf, conf_enc_len, dec_buf);
            dec_buf[conf_dec_len] = '\0';
            printf("Server: %s\n", (char *)dec_buf);
            continue;}
        if (strncmp(message, "download ", 9) == 0) {
            char filename[256];
            sscanf(message + 9, "%255s", filename);
            enc_len = encrypt((unsigned char *)message, strlen(message), enc_buf);
            len_net = htonl(enc_len);
            send(sock, &len_net, sizeof(len_net), 0);
            send(sock, enc_buf, enc_len, 0);
            int sz_net;
            read(sock, &sz_net, sizeof(sz_net));
            int sz_enc_len = ntohl(sz_net);
            total = 0;
            while (total < sz_enc_len) {
                bytes = read(sock, enc_buf + total, sz_enc_len - total);
                if (bytes <= 0) break;
                total += bytes;}
            int sz_dec_len = decrypt(enc_buf, sz_enc_len, dec_buf);
            dec_buf[sz_dec_len] = '\0';
            int filesize = atoi((char *)dec_buf);
            if (filesize <= 0) {
                printf("Server: %s\n", (char *)dec_buf);
                continue;}
            unsigned char *enc_file = malloc(filesize + 64);
            unsigned char *dec_file = malloc(filesize + 64);
            int fd_net;
            read(sock, &fd_net, sizeof(fd_net));
            int fd_enc_len = ntohl(fd_net);
            total = 0;
            while (total < fd_enc_len) {
                bytes = read(sock, enc_file + total, fd_enc_len - total);
                if (bytes <= 0) break;
                total += bytes;}
            int fd_dec_len = decrypt(enc_file, fd_enc_len, dec_file);
            FILE *fp = fopen(filename, "wb");
            if (fp) {
                fwrite(dec_file, 1, fd_dec_len, fp);
                fclose(fp);
                printf("Downloaded: %s (%d bytes saved)\n", filename, fd_dec_len);}
            else {
                printf("Error: could not save '%s' locally.\n", filename);}
            free(enc_file);
            free(dec_file);
            continue;}
        enc_len = encrypt((unsigned char *)message, strlen(message), enc_buf);
        len_net = htonl(enc_len);
        send(sock, &len_net, sizeof(len_net), 0);
        send(sock, enc_buf, enc_len, 0);
        int reply_net;
        read(sock, &reply_net, sizeof(reply_net));
        int reply_enc_len = ntohl(reply_net);
        total = 0;
        while (total < reply_enc_len) {
            bytes = read(sock, enc_buf + total, reply_enc_len - total);
            if (bytes <= 0) break;
            total += bytes;}
        int dec_len = decrypt(enc_buf, reply_enc_len, dec_buf);
        dec_buf[dec_len] = '\0';
        printf("Server: %s\n", (char *)dec_buf);}

    close(sock);
    return 0;}
