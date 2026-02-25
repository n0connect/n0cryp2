#ifndef TCPSERVER_H
#define TCPSERVER_H

#include <openssl/ssl.h>
#include <pthread.h>
#include <stdbool.h>

#include "colorcodes.h"
#include "database.h"
#include "e2e_crypto.h"
#include "logmacro.h"
#include "protocol.h"
#include "socketutil.h"
#include "strtohex.h"
#include "tls_utils.h"

#define PORT 2000
#define QUEUE 5
#define MAX_CLIENTS 10
#define BUFFER_SIZE 4096

struct AcceptedSocket {
  int fd;
  SSL *ssl;
  struct sockaddr_in address;
  int client_id;
  uint8_t e2e_pubkey[E2E_KEY_LEN];
  bool has_e2e_key;
  bool accepted_success;
  int error;
};

/* Globals */
extern struct AcceptedSocket accepted_sockets[MAX_CLIENTS];
extern unsigned int accepted_sockets_count;
extern pthread_mutex_t accepted_sockets_mutex;

/* Functions */
void interrupt_handler(int sig);
int generate_client_id(void);
void socket_list_init(void);
void server_bind(int server_socket, struct sockaddr *server_address);
void server_listen(int server_socket);
void start_accept_connections(int server_socket, SSL_CTX *tls_ctx);
void *handle_client_thread(void *arg);

bool handle_login(SSL *ssl, int client_id);
void handle_client_messages(SSL *ssl, int client_id);
void relay_e2e_message(int sender_id, uint8_t *payload, uint16_t len);
void broadcast_client_left(int client_id);
void send_key_list(SSL *ssl, int exclude_id);
void broadcast_new_pubkey(int client_id, const uint8_t *pubkey);

#endif /* TCPSERVER_H */