/**
 * @file TCPClient.c — TLS 1.3 + E2E Encrypted Chat Client
 * Messages are encrypted end-to-end: server cannot read them.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "tcpclient.h"

/* Globals */
const char *address = "127.0.0.1";
char *username_ptr = NULL;

PeerKey known_peers[MAX_CLIENTS];
int known_peer_count = 0;
pthread_mutex_t peers_mutex = PTHREAD_MUTEX_INITIALIZER;

E2EKeyPair my_keypair;
int my_client_id = -1;
SSL *g_ssl = NULL;

/* === UI Functions === */

void newline_messagebox(void) {
  fprintf(stdout, "\n");
  if (username_ptr) {
    LOG_MSG(username_ptr, online);
  } else {
    LOG_MSG("unknown", online);
  }
  fflush(stdout);
}

void messagebox(void) {
  if (username_ptr) {
    LOG_MSG(username_ptr, online);
  } else {
    LOG_MSG("unknown", online);
  }
  fflush(stdout);
}

int get_terminal_width(void) {
  struct winsize ws;
  if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) != -1)
    return ws.ws_col;
  return 80;
}

int get_terminal_height(void) {
  struct winsize ws;
  if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) != -1)
    return ws.ws_row;
  return 20;
}

/* === Network === */

bool connect_to_server(int network_socket, struct sockaddr *server_address) {
  if (connect(network_socket, server_address, sizeof(struct sockaddr_in)) < 0) {
    LOG_ERROR(client, "Connection error: %s", strerror(errno));
    shutdown(network_socket, SHUT_RDWR);
    free(server_address);
    return false;
  }
  LOG_SUCCESS(client, "TCP connected to server.");
  return true;
}

/* === Peer management === */

static void add_peer(int client_id, const uint8_t *pubkey) {
  pthread_mutex_lock(&peers_mutex);
  /* Check if already exists */
  for (int i = 0; i < known_peer_count; i++) {
    if (known_peers[i].client_id == client_id) {
      memcpy(known_peers[i].public_key, pubkey, E2E_KEY_LEN);
      pthread_mutex_unlock(&peers_mutex);
      return;
    }
  }
  if (known_peer_count < MAX_CLIENTS) {
    known_peers[known_peer_count].client_id = client_id;
    memcpy(known_peers[known_peer_count].public_key, pubkey, E2E_KEY_LEN);
    known_peer_count++;
  }
  pthread_mutex_unlock(&peers_mutex);
}

static void remove_peer(int client_id) {
  pthread_mutex_lock(&peers_mutex);
  for (int i = 0; i < known_peer_count; i++) {
    if (known_peers[i].client_id == client_id) {
      for (int j = i; j < known_peer_count - 1; j++) {
        known_peers[j] = known_peers[j + 1];
      }
      known_peer_count--;
      break;
    }
  }
  pthread_mutex_unlock(&peers_mutex);
}

static const uint8_t *find_peer_pubkey(int client_id) {
  /* Must hold peers_mutex */
  for (int i = 0; i < known_peer_count; i++) {
    if (known_peers[i].client_id == client_id)
      return known_peers[i].public_key;
  }
  return NULL;
}

/* === Login === */

static char *prompt_input(const char *prompt) {
  char *line = NULL;
  size_t len = 0;
  fprintf(stdout, BCYN "%s" RESET, prompt);
  fflush(stdout);
  if (getline(&line, &len, stdin) <= 0) {
    free(line);
    return NULL;
  }
  line[strcspn(line, "\n")] = '\0';
  return line;
}

bool do_login(SSL *ssl) {
  while (true) {
    char *username = prompt_input("  - Username: ");
    if (!username)
      return false;
    char *password = prompt_input("  - Password: ");
    if (!password) {
      free(username);
      return false;
    }

    char creds[128];
    snprintf(creds, sizeof(creds), "%s:%s", username, password);

    /* Store username for UI */
    if (username_ptr)
      free(username_ptr);
    username_ptr = (char *)malloc(strlen(username) + 1);
    strcpy(username_ptr, username);

    free(username);
    free(password);

    /* Send login (plaintext over TLS — safe!) */
    protocol_send(ssl, MSG_LOGIN_REQ, creds, (uint16_t)strlen(creds));
    LOG_SUCCESS(client, "Login credentials sent (protected by TLS).");

    /* Receive response */
    uint8_t type;
    uint8_t *payload = NULL;
    uint16_t len;
    if (protocol_recv(ssl, &type, &payload, &len) < 0) {
      LOG_ERROR(client, "Server disconnected during login.");
      return false;
    }

    if (type == MSG_LOGIN_RES && len >= 5 && payload[0] == 1) {
      int32_t net_id;
      memcpy(&net_id, payload + 1, 4);
      my_client_id = ntohl(net_id);
      LOG_SUCCESS(client, "Login successful! Client ID: %d", my_client_id);
      free(payload);

      fprintf(stdout, "\033[2J\033[H");
      fflush(stdout);
      return true;
    } else {
      LOG_ERROR(client, "Login failed. Try again.");
      free(payload);
      sleep(1);
      fprintf(stdout, "\033[2J\033[H");
      fflush(stdout);
    }
  }
}

/* === E2E key exchange === */

void send_my_pubkey(SSL *ssl) {
  uint8_t payload[4 + E2E_KEY_LEN];
  int32_t net_id = htonl(my_client_id);
  memcpy(payload, &net_id, 4);
  memcpy(payload + 4, my_keypair.public_key, E2E_KEY_LEN);

  protocol_send(ssl, MSG_PUB_KEY, payload, sizeof(payload));

  char *hex = str_to_hex((const char *)my_keypair.public_key, E2E_KEY_LEN);
  LOG_SUCCESS(client, "E2E public key sent: %s", hex);
  free(hex);
}

static void process_key_list(uint8_t *payload, uint16_t len) {
  if (len < 4)
    return;
  int32_t net_count;
  memcpy(&net_count, payload, 4);
  int count = ntohl(net_count);
  LOG_INFO(client, "Received %d peer keys.", count);

  int offset = 4;
  for (int i = 0; i < count && offset + 4 + E2E_KEY_LEN <= len; i++) {
    int32_t net_id;
    memcpy(&net_id, payload + offset, 4);
    int peer_id = ntohl(net_id);
    offset += 4;
    add_peer(peer_id, payload + offset);
    offset += E2E_KEY_LEN;
    LOG_INFO(client, "  Peer[%d] key stored.", peer_id);
  }
}

/* === E2E send === */

void e2e_send_to_all(SSL *ssl, const char *message) {
  pthread_mutex_lock(&peers_mutex);
  int count = known_peer_count;

  if (count == 0) {
    pthread_mutex_unlock(&peers_mutex);
    LOG_INFO(client, "No peers connected, message not sent.");
    return;
  }

  for (int i = 0; i < count; i++) {
    int target_id = known_peers[i].client_id;
    const uint8_t *peer_pub = known_peers[i].public_key;

    /* Derive shared AES key */
    uint8_t aes_key[E2E_KEY_LEN];
    if (e2e_derive_key(my_keypair.private_key, peer_pub, aes_key) < 0) {
      LOG_ERROR(client, "Failed to derive key for peer[%d].", target_id);
      continue;
    }

    /* Encrypt */
    uint8_t nonce[E2E_NONCE_LEN];
    uint8_t ciphertext[BUFFER_SIZE];
    int ct_len = 0;
    int msg_len = (int)strlen(message);

    if (e2e_encrypt(aes_key, (const uint8_t *)message, msg_len, nonce,
                    ciphertext, &ct_len) < 0) {
      LOG_ERROR(client, "E2E encrypt failed for peer[%d].", target_id);
      continue;
    }

    /* Build payload: [int32 target_id][12 nonce][ciphertext+tag] */
    uint16_t payload_len = 4 + E2E_NONCE_LEN + (uint16_t)ct_len;
    uint8_t *payload = (uint8_t *)malloc(payload_len);
    if (!payload)
      continue;

    int32_t net_target = htonl(target_id);
    memcpy(payload, &net_target, 4);
    memcpy(payload + 4, nonce, E2E_NONCE_LEN);
    memcpy(payload + 4 + E2E_NONCE_LEN, ciphertext, ct_len);

    protocol_send(ssl, MSG_E2E_MSG, payload, payload_len);
    free(payload);

    OPENSSL_cleanse(aes_key, sizeof(aes_key));
  }

  pthread_mutex_unlock(&peers_mutex);
  LOG_SUCCESS(client, "E2E message sent to %d peers.", count);
}

/* === Listening thread === */

void start_listening_thread(SSL *ssl) {
  pthread_t tid;
  SSL **ssl_copy = (SSL **)malloc(sizeof(SSL *));
  *ssl_copy = ssl;
  if (pthread_create(&tid, NULL, listening_thread, ssl_copy) != 0) {
    LOG_ERROR(client, "Failed to create listening thread.");
    free(ssl_copy);
    exit(EXIT_FAILURE);
  }
  pthread_detach(tid);
}

void *listening_thread(void *arg) {
  SSL *ssl = *(SSL **)arg;
  free(arg);

  int terminal_width = get_terminal_width();
  size_t half_width = (size_t)terminal_width / 2;

  while (true) {
    uint8_t type;
    uint8_t *payload = NULL;
    uint16_t len;

    if (protocol_recv(ssl, &type, &payload, &len) < 0) {
      LOG_ERROR(client, "Connection to server lost.");
      break;
    }

    switch (type) {
    case MSG_E2E_MSG: {
      /* [int32 sender_id][12 nonce][ciphertext+tag] */
      if (len < 4 + E2E_NONCE_LEN + E2E_TAG_LEN) {
        LOG_ERROR(client, "E2E message too short.");
        break;
      }
      int32_t net_sender;
      memcpy(&net_sender, payload, 4);
      int sender_id = ntohl(net_sender);

      const uint8_t *nonce = payload + 4;
      const uint8_t *ct = payload + 4 + E2E_NONCE_LEN;
      int ct_len = len - 4 - E2E_NONCE_LEN;

      /* Find sender's public key */
      pthread_mutex_lock(&peers_mutex);
      const uint8_t *sender_pub = find_peer_pubkey(sender_id);
      if (!sender_pub) {
        pthread_mutex_unlock(&peers_mutex);
        LOG_ERROR(client, "Unknown sender[%d], cannot decrypt.", sender_id);
        break;
      }

      /* Derive shared key */
      uint8_t aes_key[E2E_KEY_LEN];
      uint8_t sender_pub_copy[E2E_KEY_LEN];
      memcpy(sender_pub_copy, sender_pub, E2E_KEY_LEN);
      pthread_mutex_unlock(&peers_mutex);

      if (e2e_derive_key(my_keypair.private_key, sender_pub_copy, aes_key) <
          0) {
        LOG_ERROR(client, "Key derivation failed for sender[%d].", sender_id);
        break;
      }

      /* Decrypt */
      uint8_t plaintext[BUFFER_SIZE];
      int pt_len = 0;
      if (e2e_decrypt(aes_key, nonce, ct, ct_len, plaintext, &pt_len) < 0) {
        LOG_ERROR(client, "E2E decryption FAILED (auth error) from sender[%d].",
                  sender_id);
        break;
      }
      plaintext[pt_len] = '\0';
      OPENSSL_cleanse(aes_key, sizeof(aes_key));

      /* Display message */
      fprintf(stdout, "\r");
      size_t msg_len = strlen((char *)plaintext);
      if (half_width < msg_len) {
        fprintf(stdout, BCYN "%*s%.*s" RESET "\n", (int)half_width, "",
                (int)msg_len, (char *)plaintext);
      } else {
        fprintf(stdout, BCYN "%*s%s" RESET "\n", (int)half_width, "",
                (char *)plaintext);
      }
      fflush(stdout);
      newline_messagebox();
      break;
    }

    case MSG_PUB_KEY: {
      if (len >= 4 + E2E_KEY_LEN) {
        int32_t net_id;
        memcpy(&net_id, payload, 4);
        int peer_id = ntohl(net_id);
        add_peer(peer_id, payload + 4);
        LOG_INFO(client, "New peer[%d] joined, key stored.", peer_id);
      }
      break;
    }

    case MSG_KEY_LIST:
      process_key_list(payload, len);
      break;

    case MSG_CLIENT_LEFT: {
      if (len >= 4) {
        int32_t net_id;
        memcpy(&net_id, payload, 4);
        int peer_id = ntohl(net_id);
        remove_peer(peer_id);
        LOG_INFO(client, "Peer[%d] disconnected, key removed.", peer_id);
      }
      break;
    }

    default:
      LOG_ERROR(client, "Unknown message type: 0x%02x", type);
      break;
    }

    free(payload);
  }

  return NULL;
}

/* === Chat loop === */

void chat_loop(SSL *ssl, char *username) {
  char *terminal_line = NULL;
  size_t terminal_line_size = 0;

  newline_messagebox();

  while (true) {
    free(terminal_line);
    terminal_line = NULL;
    terminal_line_size = 0;

    ssize_t n = getline(&terminal_line, &terminal_line_size, stdin);
    if (n <= 0)
      continue;

    if (n == 1 && terminal_line[0] == '\n') {
      printf("\r\033[K");
      messagebox();
      fflush(stdout);
      continue;
    }

    terminal_line[strcspn(terminal_line, "\n")] = '\0';

    if (strcmp(terminal_line, "/exit") == 0 ||
        strcmp(terminal_line, "/quit") == 0) {
      break;
    }

    /* Build message: "username: message" */
    char msg_buf[BUFFER_SIZE];
    snprintf(msg_buf, sizeof(msg_buf), "%s: %s", username, terminal_line);

    /* E2E encrypt and send to all peers */
    e2e_send_to_all(ssl, msg_buf);
    newline_messagebox();
  }

  free(terminal_line);
}

/* === Main === */

int main(void) {
  int network_socket = createTCPIp4Socket();
  struct sockaddr_in *server_address = createIPv4Address(address, PORT);

  if (!connect_to_server(network_socket, (struct sockaddr *)server_address)) {
    exit(EXIT_FAILURE);
  }

  /* TLS handshake */
  SSL_CTX *tls_ctx = create_client_tls_context();
  if (!tls_ctx)
    exit(EXIT_FAILURE);

  SSL *ssl = tls_client_connect(tls_ctx, network_socket);
  if (!ssl)
    exit(EXIT_FAILURE);
  g_ssl = ssl;

  /* Login */
  if (!do_login(ssl)) {
    LOG_ERROR(client, "Login failed. Exiting.");
    tls_cleanup(ssl);
    SSL_CTX_free(tls_ctx);
    exit(EXIT_FAILURE);
  }

  /* Generate E2E keypair */
  if (e2e_generate_keypair(&my_keypair) < 0) {
    LOG_ERROR(client, "Failed to generate E2E keypair.");
    exit(EXIT_FAILURE);
  }

  /* Send public key to server */
  send_my_pubkey(ssl);

  /* Receive initial key list + start listening */
  {
    uint8_t type;
    uint8_t *payload = NULL;
    uint16_t len;
    if (protocol_recv(ssl, &type, &payload, &len) == 0 &&
        type == MSG_KEY_LIST) {
      process_key_list(payload, len);
      free(payload);
    }
  }

  start_listening_thread(ssl);

  /* Chat! */
  LOG_SUCCESS(client, "=== n0cryp2 E2E Encrypted Chat ===");
  LOG_INFO(client,
           "Messages are end-to-end encrypted. Server cannot read them.");
  chat_loop(ssl, username_ptr);

  /* Cleanup */
  tls_cleanup(ssl);
  SSL_CTX_free(tls_ctx);
  shutdown(network_socket, SHUT_RDWR);
  close(network_socket);
  free(username_ptr);

  return 0;
}