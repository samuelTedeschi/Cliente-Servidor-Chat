#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 8080
#define BUF_SIZE 1024

void *receive_messages(void *arg);
void init_openssl();
void cleanup_openssl();
SSL_CTX *create_context();
void configure_context(SSL_CTX *ctx);


int main() {
    int sock = 0;
    struct sockaddr_in serv_addr;
    pthread_t tid;
    char buffer[BUF_SIZE] = {0};
    SSL_CTX *ctx;
    SSL *ssl;

    // Inicializa o OpenSSL
    init_openssl();
    ctx = create_context();
    configure_context(ctx);

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("\nConnection Failed \n");
        return -1;
    }

    // Cria a estrutura SSL e estabelece uma conexão
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        printf("Conectado ao servidor\n");
        pthread_create(&tid, NULL, receive_messages, (void *)ssl);

        while (1) {
            fgets(buffer, BUF_SIZE, stdin);
            SSL_write(ssl, buffer, strlen(buffer));
        }
    }

    close(sock);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    return 0;
}

void *receive_messages(void *arg) {
    SSL *ssl = (SSL *)arg;
    char buffer[BUF_SIZE];
    int nbytes;

    while ((nbytes = SSL_read(ssl, buffer, BUF_SIZE)) > 0) {
        buffer[nbytes] = '\0';
        printf("Servidor: %s", buffer);
    }

    return NULL;
}

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_client_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    // Configurações adicionais para o contexto SSL
    SSL_CTX_set_ecdh_auto(ctx, 1);
}
