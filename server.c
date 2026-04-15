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
    int  file_level;
    if (!file) return 0;
    pass[strcspn(pass, "\r\n")] = 0;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    char hash_str[65];
    SHA256((unsigned char *)pass, strlen(pass), hash);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hash_str + (i * 2), "%02x", hash[i]);}
    hash_str[64] = '\0';
    while (fscanf(file, "%s %s %d", file_user, file_hash, &file_level) == 3) {
        if (strcmp(user, file_user) == 0 &&
            strcmp(hash_str, file_hash) == 0) {
            fclose(file);
            return file_level;}}
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
    int n = read(sock, buffer, BUFFER_SIZE - 1);
    if (n <= 0) { close(sock); return NULL; }
    buffer[n] = '\0';
    char username[50], password[50];
    sscanf(buffer, "%s %s", username, password);
    int level = authenticate(username, password);
    if (level == 0) {
        send(sock, "AUTH_FAILED", 11, 0);
        close(sock);
        return NULL;}
    char auth_msg[32];
    sprintf(auth_msg, "AUTH_SUCCESS %d", level);
    send(sock, auth_msg, strlen(auth_msg), 0);
    printf("Authenticated: %s (level %d)\n", username, level);
    while (1) {
        unsigned char enc_buf[BUFFER_SIZE * 4];
        unsigned char dec_buf[BUFFER_SIZE * 4];
        char reply[BUFFER_SIZE * 3];
        int len_net, enc_len, total, bytes;
        int r = read(sock, &len_net, sizeof(len_net));
        if (r <= 0) break;
        enc_len = ntohl(len_net);
        if (enc_len <= 0 || enc_len > (int)sizeof(enc_buf)) break;
        total = 0;
        while (total < enc_len) {
            bytes = read(sock, enc_buf + total, enc_len - total);
            if (bytes <= 0) { close(sock); return NULL; }
            total += bytes;}
        int dec_len = decrypt(enc_buf, enc_len, dec_buf);
        dec_buf[dec_len] = '\0';
        printf("Client %s: %s\n", username, (char *)dec_buf);
        char *cmd = (char *)dec_buf;
        reply[0] = '\0';
        if (strcmp(cmd, "exit") == 0) {
            break;}
        else if (strcmp(cmd, "ls") == 0) {
            FILE *pipe = popen("ls", "r");
            char line[256];
            while (fgets(line, sizeof(line), pipe))
                strncat(reply, line, sizeof(reply) - strlen(reply) - 1);
            pclose(pipe);
            if (reply[0] == '\0') strcpy(reply, "(directory is empty)");}
        else if (strncmp(cmd, "cat ", 4) == 0) {
            char filename[256];
            sscanf(cmd + 4, "%255s", filename);
            FILE *fp = fopen(filename, "r");
            if (!fp) {
                strcpy(reply, "error file not found.");} 
            else {
                char line[256];
                while (fgets(line, sizeof(line), fp))
                    strncat(reply, line, sizeof(reply) - strlen(reply) - 1);
                fclose(fp);
                if (reply[0] == '\0') strcpy(reply, "(empty file)");}}
        else if (strncmp(cmd, "cp ", 3) == 0) {
            if (level < 2) {
                strcpy(reply, "access denied Level 2 required.");} 
            else {
                char src[256], dst[256];
                sscanf(cmd + 3, "%255s %255s", src, dst);
                FILE *fsrc = fopen(src, "rb");
                if (!fsrc) {
                    strcpy(reply, "Error");} 
                else {
                    FILE *fdst = fopen(dst, "wb");
                    if (!fdst) {
                        fclose(fsrc);
                        strcpy(reply, "Error");} 
                    else {
                        char buf[512];
                        size_t nb;
                        while ((nb = fread(buf, 1, sizeof(buf), fsrc)) > 0)
                            fwrite(buf, 1, nb, fdst);
                        fclose(fsrc);
                        fclose(fdst);
                        strcpy(reply, "File copied successfully.");}}}}
        else if (strncmp(cmd, "edit ", 5) == 0) {
            if (level < 2) {
                strcpy(reply, "access denied Level 2 required.");} 
            else {
                char filename[256];
                sscanf(cmd + 5, "%255s", filename);
                char *text = cmd + 5 + strlen(filename);
                if (*text == ' ') text++;
                FILE *fp = fopen(filename, "a");
                if (!fp) {
                    strcpy(reply, "error cannot open file for editing.");} 
                else {
                    fprintf(fp, "%s\n", text);
                    fclose(fp);
                    strcpy(reply, "file edited successfully.");}}}
        else if (strncmp(cmd, "rm ", 3) == 0) {
            if (level < 3) {
                strcpy(reply, "access denied Level 3 required.");} 
            else {
                char filename[256];
                sscanf(cmd + 3, "%255s", filename);
                if (remove(filename) == 0)
                    strcpy(reply, "file deleted successfully.");
                else
                    strcpy(reply, "error could not delete file.");}}
        else if (strncmp(cmd, "upload ", 7) == 0) {
            if (level < 3) {
                strcpy(reply, "access denied: Level 3 required.");} 
            else {
                char filename[256];
                sscanf(cmd + 7, "%255s", filename);
                char ready[] = "READY";
                int ready_enc_len = encrypt((unsigned char *)ready, strlen(ready), enc_buf);
                int ready_net = htonl(ready_enc_len);
                send(sock, &ready_net, sizeof(ready_net), 0);
                send(sock, enc_buf, ready_enc_len, 0);
                unsigned char enc_sz[BUFFER_SIZE + 32];
                unsigned char dec_sz[64];
                int sz_net;
                read(sock, &sz_net, sizeof(sz_net));
                int sz_enc_len = ntohl(sz_net);
                total = 0;
                while (total < sz_enc_len) {
                    bytes = read(sock, enc_sz + total, sz_enc_len - total);
                    if (bytes <= 0) { close(sock); return NULL; }
                    total += bytes;}
                int sz_dec_len = decrypt(enc_sz, sz_enc_len, dec_sz);
                dec_sz[sz_dec_len] = '\0';
                int filesize = atoi((char *)dec_sz);
                unsigned char *enc_file = malloc(filesize + 64);
                unsigned char *dec_file = malloc(filesize + 64);
                int fd_net;
                read(sock, &fd_net, sizeof(fd_net));
                int fd_enc_len = ntohl(fd_net);
                total = 0;
                while (total < fd_enc_len) {
                    bytes = read(sock, enc_file + total, fd_enc_len - total);
                    if (bytes <= 0) { free(enc_file); free(dec_file); close(sock); return NULL; }
                    total += bytes;}
                int fd_dec_len = decrypt(enc_file, fd_enc_len, dec_file);
                FILE *fp = fopen(filename, "wb");
                if (fp) {
                    fwrite(dec_file, 1, fd_dec_len, fp);
                    fclose(fp);
                    strcpy(reply, "upload successful.");} 
                else {
                    strcpy(reply, "error: server could not save file.");}
                free(enc_file);
                free(dec_file);}}
        else if (strncmp(cmd, "download ", 9) == 0) {
            if (level < 3) {
                strcpy(reply, "access denied Level 3 required.");} 
            else {
                char filename[256];
                sscanf(cmd + 9, "%255s", filename);
                FILE *fp = fopen(filename, "rb");
                if (!fp) {
                    strcpy(reply, "error file not found.");} 
                else {
                    fseek(fp, 0, SEEK_END);
                    int filesize = (int)ftell(fp);
                    rewind(fp);
                    char size_str[32];
                    sprintf(size_str, "%d", filesize);
                    unsigned char enc_sz[BUFFER_SIZE + 32];
                    int sz_enc_len = encrypt((unsigned char *)size_str, strlen(size_str), enc_sz);
                    int sz_net = htonl(sz_enc_len);
                    send(sock, &sz_net, sizeof(sz_net), 0);
                    send(sock, enc_sz, sz_enc_len, 0);
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
                    continue;}}}
        else {
            strcpy(reply, "unknown command ,try: ls, cat, cp, edit, rm, upload, download");}
        int reply_enc_len = encrypt((unsigned char *)reply, strlen(reply), enc_buf);
        int reply_net = htonl(reply_enc_len);
        send(sock, &reply_net, sizeof(reply_net), 0);
        send(sock, enc_buf, reply_enc_len, 0);}

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
    printf("Server listening on port 8080.......\n");
    while (1) {
        int addrlen = sizeof(address);
        int *new_socket = malloc(sizeof(int));
        *new_socket = accept(server_fd, (struct sockaddr *)&address,
                             (socklen_t *)&addrlen);
        pthread_t thread_id;
        pthread_create(&thread_id, NULL, handle_client, (void *)new_socket);
        pthread_detach(thread_id);}
    return 0;}
