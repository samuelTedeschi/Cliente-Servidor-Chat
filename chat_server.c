#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <opensll/err.h>

#define PORT 8080
#define BUF_SIZE 1024
#define MAX_CLIENTS 100

SSL_CTX *ctx;

void *handle_client(void *arg);
void send_message_to_all(char *message, int exclude_fd);
void init_openssl();
void cleanup_openssl();
SSL_CTX *create_context();
void configure_context(SSL_CTX *ctx);

int client_sockets[MAX_CLIENTS];
SSL *client_ssl[MAX_CLIENTS];
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    // Inicializa o OpenSSL
    init_openssl();
    ctx = create_context();
    configure_context(ctx);

    // Configura o servidor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Servidor rodando na porta %d\n", PORT);

    while ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) >= 0) {
        pthread_t tid;
        SSL *ssl;

        // Cria a estrutura SSL
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, new_socket);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            close(new_socket);
            SSL_free(ssl);
        } else {
            printf("Cliente conectado\n");
            pthread_mutex_lock(&clients_mutex);
            for (int i = 0; i < MAX_CLIENTS; ++i) {
                if (client_sockets[i] == 0) {
                    client_sockets[i] = new_socket;
                    client_ssl[i] = ssl;
                    pthread_create(&tid, NULL, handle_client, (void *)ssl);
                    break;
                }
            }
            pthread_mutex_unlock(&clients_mutex);
        }
    }

    close(server_fd);
    cleanup_openssl();
    return 0;
}

void *handle_client(void *arg) {
    SSL *ssl = (SSL *)arg;
    char buffer[BUF_SIZE];
    int nbytes;

    while ((nbytes = SSL_read(ssl, buffer, BUF_SIZE)) > 0) {
        buffer[nbytes] = '\0';
        printf("Mensagem recebida: %s", buffer);
        send_message_to_all(buffer, SSL_get_fd(ssl));
    }

    close(SSL_get_fd(ssl));
    SSL_free(ssl);

    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; ++i) {
        if (client_sockets[i] == SSL_get_fd(ssl)) {
            client_sockets[i] = 0;
            client_ssl[i] = NULL;
            break;
        }
    }
    pthread_mutex_unlock(&clients_mutex);

    return NULL;
}

void send_message_to_all(char *message, int exclude_fd) {
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; ++i) {
        if (client_sockets[i] != 0 && client_sockets[i] != exclude_fd) {
            SSL_write(client_ssl[i], message, strlen(message));
        }
    }
    pthread_mutex_unlock(&clients_mutex);
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

    method = SSLv23_server_method();

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

    // Carrega os certificados do servidor
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}
