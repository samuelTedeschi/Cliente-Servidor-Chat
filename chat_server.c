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

int client_sockets[MAX_CLIENTS];
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;

int main (){

    int serve_fd, new_socked;
    struct sockaddr_in address;
    int addrlen = sizeof(address);

    // inicializa o OpenSSL
    init_openssl();
    cxt = create_context();

    //configurar servidor
    if ((server_fd = socket(AF_INET, SOCKET_STREAM, 0)) == 0 ){
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(serve_fd, (struct sockaddr *)&address, sizeof(address)) < 0){
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0){
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Servidor rodando na porta %d\n", PORT);

    while ((new_socked = accept(serve_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) >= 0){
        pthread_t tid;
        SSL *ssl;

        //criar a estrutura SSL
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, new_socked);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        }else {
            pthread_mutex_lock(&clients_mutex);
            for (int i = 0, i < MAX_CLIENTS; i++){
                if (client_sockets[i] == 0){
                    client_sockets[i] == new_socked;
                    pthread_create(&tid, NULL, handle_client, (void *)ssl);
                    break;
                }
            }
            pthread_mutex_unlock(&clients_mutex);
        }
    }

    close(serve_fd);
    cleanup_openssl();
    return 0;

}
