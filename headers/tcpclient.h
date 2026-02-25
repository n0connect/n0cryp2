#ifndef TCPCLIENT_H
#define TCPCLIENT_H

#include <openssl/ssl.h>
#include <stdbool.h>

#include "colorcodes.h"
#include "e2e_crypto.h"
#include "logmacro.h"
#include "protocol.h"
#include "socketutil.h"
#include "strtohex.h"
#include "tls_utils.h"

#define PORT 2000
#define MAX_CLIENTS 10
#define BUFFER_SIZE 4096

extern const char *address;

/* Peer key storage */
typedef struct {
  int client_id;
  uint8_t public_key[E2E_KEY_LEN];
} PeerKey;

extern PeerKey known_peers[MAX_CLIENTS];
extern int known_peer_count;
extern pthread_mutex_t peers_mutex;

extern E2EKeyPair my_keypair;
extern int my_client_id;
extern SSL *g_ssl;

/* UI */
void newline_messagebox(void);
void messagebox(void);
int get_terminal_width(void);
int get_terminal_height(void);

/* Network */
bool connect_to_server(int network_socket, struct sockaddr *server_address);
bool do_login(SSL *ssl);
void send_my_pubkey(SSL *ssl);
void e2e_send_to_all(SSL *ssl, const char *message);

/* Threads */
void start_listening_thread(SSL *ssl);
void *listening_thread(void *arg);

/* Main flow */
void chat_loop(SSL *ssl, char *username);

#endif /* TCPCLIENT_H */