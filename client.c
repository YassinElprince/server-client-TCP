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
