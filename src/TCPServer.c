/**
 * @file TCPServer.c — TLS 1.3 + E2E Encrypted Chat Server
 * Server is a RELAY — it cannot read E2E messages.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include "tcpserver.h"

#define CERT_PATH "server-key/server.crt"
#define KEY_PATH "server-key/server.key"

/* Globals */
struct AcceptedSocket accepted_sockets[MAX_CLIENTS];
unsigned int accepted_sockets_count = 0;
pthread_mutex_t accepted_sockets_mutex = PTHREAD_MUTEX_INITIALIZER;

static int g_server_socket_fd = -1;
static int g_next_client_id = 1;
static pthread_mutex_t id_mutex = PTHREAD_MUTEX_INITIALIZER;

/* --- Signal handler (async-signal-safe) --- */
void interrupt_handler(int sig) {
  (void)sig;
  const char msg[] = "\n[SIGNAL] Server shutting down.\n";
  write(STDERR_FILENO, msg, sizeof(msg) - 1);
  if (g_server_socket_fd >= 0) {
    shutdown(g_server_socket_fd, SHUT_RDWR);
    close(g_server_socket_fd);
  }
  _exit(EXIT_SUCCESS);
}

int generate_client_id(void) {
  pthread_mutex_lock(&id_mutex);
  int id = g_next_client_id++;
  pthread_mutex_unlock(&id_mutex);
  return id;
}

void socket_list_init(void) {
  memset(accepted_sockets, 0, sizeof(accepted_sockets));
  accepted_sockets_count = 0;
}

void server_bind(int server_socket, struct sockaddr *server_address) {
  int opt = 1;
  setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
  if (bind(server_socket, server_address, sizeof(struct sockaddr_in)) < 0) {
    LOG_ERROR(server, "Bind error: %s", strerror(errno));
    exit(EXIT_FAILURE);
  }
  LOG_SUCCESS(server, "Socket bound successfully.");
}

void server_listen(int server_socket) {
  if (listen(server_socket, QUEUE) < 0) {
    LOG_ERROR(server, "Listen error");
    exit(EXIT_FAILURE);
  }
  LOG_INFO(server, "Listening for connections on port %d...", PORT);
}

/* --- Key distribution --- */

void send_key_list(SSL *ssl, int exclude_id) {
  pthread_mutex_lock(&accepted_sockets_mutex);

  /* Count peers with keys */
  int count = 0;
  for (unsigned int i = 0; i < accepted_sockets_count; i++) {
    if (accepted_sockets[i].has_e2e_key &&
        accepted_sockets[i].client_id != exclude_id)
      count++;
  }

  /* Build payload: [int32 count][{int32 id, 32B key} × count] */
  uint16_t payload_len = 4 + count * (4 + E2E_KEY_LEN);
  uint8_t *payload = (uint8_t *)calloc(1, payload_len);
  if (!payload) {
    pthread_mutex_unlock(&accepted_sockets_mutex);
    return;
  }

  int32_t net_count = htonl(count);
  memcpy(payload, &net_count, 4);

  int offset = 4;
  for (unsigned int i = 0; i < accepted_sockets_count; i++) {
    if (accepted_sockets[i].has_e2e_key &&
        accepted_sockets[i].client_id != exclude_id) {
      int32_t net_id = htonl(accepted_sockets[i].client_id);
      memcpy(payload + offset, &net_id, 4);
      offset += 4;
      memcpy(payload + offset, accepted_sockets[i].e2e_pubkey, E2E_KEY_LEN);
      offset += E2E_KEY_LEN;
    }
  }

  pthread_mutex_unlock(&accepted_sockets_mutex);

  protocol_send(ssl, MSG_KEY_LIST, payload, payload_len);
  LOG_INFO(server, "Sent key list (%d peers) to client.", count);
  free(payload);
}

void broadcast_new_pubkey(int client_id, const uint8_t *pubkey) {
  /* Payload: [int32 client_id][32B pubkey] */
  uint8_t payload[4 + E2E_KEY_LEN];
  int32_t net_id = htonl(client_id);
  memcpy(payload, &net_id, 4);
  memcpy(payload + 4, pubkey, E2E_KEY_LEN);

  pthread_mutex_lock(&accepted_sockets_mutex);
  for (unsigned int i = 0; i < accepted_sockets_count; i++) {
    if (accepted_sockets[i].client_id != client_id && accepted_sockets[i].ssl) {
      protocol_send(accepted_sockets[i].ssl, MSG_PUB_KEY, payload,
                    sizeof(payload));
    }
  }
  pthread_mutex_unlock(&accepted_sockets_mutex);
  LOG_INFO(server, "Broadcast pubkey for client[%d] to all peers.", client_id);
}

void broadcast_client_left(int client_id) {
  uint8_t payload[4];
  int32_t net_id = htonl(client_id);
  memcpy(payload, &net_id, 4);

  pthread_mutex_lock(&accepted_sockets_mutex);
  for (unsigned int i = 0; i < accepted_sockets_count; i++) {
    if (accepted_sockets[i].client_id != client_id && accepted_sockets[i].ssl) {
      protocol_send(accepted_sockets[i].ssl, MSG_CLIENT_LEFT, payload, 4);
    }
  }
  pthread_mutex_unlock(&accepted_sockets_mutex);
  LOG_INFO(server, "Broadcast client[%d] left.", client_id);
}

void relay_e2e_message(int sender_id, uint8_t *payload, uint16_t len) {
  /* payload from client: [int32 target_id][12 nonce][ciphertext+tag] */
  if (len < 4 + E2E_NONCE_LEN + E2E_TAG_LEN) {
    LOG_ERROR(server, "E2E message too short (%u bytes)", len);
    return;
  }

  int32_t net_target_id;
  memcpy(&net_target_id, payload, 4);
  int target_id = ntohl(net_target_id);

  /* Build delivery payload: [int32 sender_id][12 nonce][ciphertext+tag] */
  uint16_t delivery_len = 4 + (len - 4); /* replace target_id with sender_id */
  uint8_t *delivery = (uint8_t *)malloc(delivery_len);
  if (!delivery)
    return;

  int32_t net_sender = htonl(sender_id);
  memcpy(delivery, &net_sender, 4);
  memcpy(delivery + 4, payload + 4, len - 4); /* nonce + ciphertext+tag */

  /* Find target and send */
  bool sent = false;
  pthread_mutex_lock(&accepted_sockets_mutex);
  for (unsigned int i = 0; i < accepted_sockets_count; i++) {
    if (accepted_sockets[i].client_id == target_id && accepted_sockets[i].ssl) {
      protocol_send(accepted_sockets[i].ssl, MSG_E2E_MSG, delivery,
                    delivery_len);
      sent = true;
      break;
    }
  }
  pthread_mutex_unlock(&accepted_sockets_mutex);

  if (sent) {
    LOG_INFO(
        server,
        "Relayed E2E message: client[%d] → client[%d] (%u bytes, ENCRYPTED)",
        sender_id, target_id, len - 4 - E2E_NONCE_LEN);
  } else {
    LOG_ERROR(server, "Target client[%d] not found for relay.", target_id);
  }
  free(delivery);
}

/* --- Login --- */

bool handle_login(SSL *ssl, int client_id) {
  LOG_INFO(server, "Waiting for login from client[%d]...", client_id);

  while (true) {
    uint8_t type;
    uint8_t *payload = NULL;
    uint16_t len;

    if (protocol_recv(ssl, &type, &payload, &len) < 0) {
      LOG_ERROR(server, "Client[%d] disconnected during login.", client_id);
      return false;
    }

    if (type != MSG_LOGIN_REQ) {
      LOG_ERROR(server, "Expected LOGIN_REQ, got type 0x%02x", type);
      free(payload);
      continue;
    }

    /* Parse credentials (plaintext over TLS — safe) */
    char creds[256];
    int copy_len = len < 255 ? len : 255;
    memcpy(creds, payload, copy_len);
    creds[copy_len] = '\0';
    free(payload);

    char username[32], password[64];
    int parsed = sscanf(creds, "%31[^:]:%63[^\n]", username, password);

    uint8_t response[5]; /* [uint8 ok][int32 client_id] */
    if (parsed == 2 && check_credentials(username, password)) {
      response[0] = 1;
      int32_t net_id = htonl(client_id);
      memcpy(response + 1, &net_id, 4);
      protocol_send(ssl, MSG_LOGIN_RES, response, 5);
      LOG_SUCCESS(server, "Client[%d] logged in as '%s'.", client_id, username);
      return true;
    } else {
      response[0] = 0;
      memset(response + 1, 0, 4);
      protocol_send(ssl, MSG_LOGIN_RES, response, 5);
      LOG_INFO(server, "Client[%d] login failed.", client_id);
    }
  }
}

/* --- Client thread --- */

void *handle_client_thread(void *arg) {
  struct AcceptedSocket *info = (struct AcceptedSocket *)arg;
  int client_id = info->client_id;
  SSL *ssl = info->ssl;

  /* 1. Login */
  if (!handle_login(ssl, client_id)) {
    goto cleanup;
  }

  /* 2. Receive client's E2E public key */
  {
    uint8_t type;
    uint8_t *payload = NULL;
    uint16_t len;
    if (protocol_recv(ssl, &type, &payload, &len) < 0 || type != MSG_PUB_KEY) {
      LOG_ERROR(server, "Client[%d]: expected PUB_KEY after login.", client_id);
      free(payload);
      goto cleanup;
    }

    if (len < 4 + E2E_KEY_LEN) {
      LOG_ERROR(server, "Client[%d]: PUB_KEY payload too short.", client_id);
      free(payload);
      goto cleanup;
    }

    /* Store public key */
    pthread_mutex_lock(&accepted_sockets_mutex);
    for (unsigned int i = 0; i < accepted_sockets_count; i++) {
      if (accepted_sockets[i].client_id == client_id) {
        memcpy(accepted_sockets[i].e2e_pubkey, payload + 4, E2E_KEY_LEN);
        accepted_sockets[i].has_e2e_key = true;
        break;
      }
    }
    pthread_mutex_unlock(&accepted_sockets_mutex);

    char *hex = str_to_hex((const char *)(payload + 4), E2E_KEY_LEN);
    LOG_SUCCESS(server, "Client[%d] E2E pubkey: %s", client_id, hex);
    free(hex);
    free(payload);
  }

  /* 3. Send existing peers' keys to this client */
  send_key_list(ssl, client_id);

  /* 4. Broadcast this client's pubkey to others */
  pthread_mutex_lock(&accepted_sockets_mutex);
  uint8_t pubkey_copy[E2E_KEY_LEN];
  for (unsigned int i = 0; i < accepted_sockets_count; i++) {
    if (accepted_sockets[i].client_id == client_id) {
      memcpy(pubkey_copy, accepted_sockets[i].e2e_pubkey, E2E_KEY_LEN);
      break;
    }
  }
  pthread_mutex_unlock(&accepted_sockets_mutex);
  broadcast_new_pubkey(client_id, pubkey_copy);

  /* 5. Message relay loop */
  LOG_INFO(server, "Client[%d] entering E2E message relay loop.", client_id);
  handle_client_messages(ssl, client_id);

cleanup:
  LOG_INFO(server, "Client[%d] disconnecting.", client_id);
  broadcast_client_left(client_id);

  /* Remove from accepted_sockets */
  pthread_mutex_lock(&accepted_sockets_mutex);
  for (unsigned int i = 0; i < accepted_sockets_count; i++) {
    if (accepted_sockets[i].client_id == client_id) {
      tls_cleanup(accepted_sockets[i].ssl);
      close(accepted_sockets[i].fd);
      for (unsigned int j = i; j < accepted_sockets_count - 1; j++) {
        accepted_sockets[j] = accepted_sockets[j + 1];
      }
      accepted_sockets_count--;
      break;
    }
  }
  pthread_mutex_unlock(&accepted_sockets_mutex);

  free(info);
  return NULL;
}

void handle_client_messages(SSL *ssl, int client_id) {
  while (true) {
    uint8_t type;
    uint8_t *payload = NULL;
    uint16_t len;

    if (protocol_recv(ssl, &type, &payload, &len) < 0) {
      LOG_ERROR(server, "Client[%d] connection lost.", client_id);
      return;
    }

    switch (type) {
    case MSG_E2E_MSG:
      LOG_INFO(
          server,
          "Client[%d] sent E2E message (%u bytes, CANNOT READ — encrypted).",
          client_id, len);
      relay_e2e_message(client_id, payload, len);
      break;
    default:
      LOG_ERROR(server, "Client[%d] sent unexpected message type 0x%02x",
                client_id, type);
      break;
    }
    free(payload);
  }
}

/* --- Accept loop --- */

void start_accept_connections(int server_socket, SSL_CTX *tls_ctx) {
  while (true) {
    pthread_mutex_lock(&accepted_sockets_mutex);
    unsigned int count = accepted_sockets_count;
    pthread_mutex_unlock(&accepted_sockets_mutex);

    if (count >= MAX_CLIENTS) {
      LOG_ERROR(server, "Max clients reached, rejecting.");
      sleep(1);
      continue;
    }

    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    int client_fd =
        accept(server_socket, (struct sockaddr *)&client_addr, &addr_len);
    if (client_fd < 0) {
      LOG_ERROR(server, "Accept failed: %s", strerror(errno));
      continue;
    }

    LOG_SUCCESS(server, "TCP connection from %s:%d",
                inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

    /* TLS handshake */
    SSL *ssl = tls_server_accept(tls_ctx, client_fd);
    if (!ssl) {
      LOG_ERROR(server, "TLS handshake failed, dropping client.");
      close(client_fd);
      continue;
    }

    int client_id = generate_client_id();

    /* Add to accepted array */
    struct AcceptedSocket *info =
        (struct AcceptedSocket *)calloc(1, sizeof(struct AcceptedSocket));
    info->fd = client_fd;
    info->ssl = ssl;
    info->address = client_addr;
    info->client_id = client_id;
    info->accepted_success = true;

    pthread_mutex_lock(&accepted_sockets_mutex);
    if (accepted_sockets_count < MAX_CLIENTS) {
      accepted_sockets[accepted_sockets_count] = *info;
      accepted_sockets_count++;
      pthread_mutex_unlock(&accepted_sockets_mutex);

      /* Spawn thread */
      pthread_t tid;
      if (pthread_create(&tid, NULL, handle_client_thread, info) != 0) {
        LOG_ERROR(server, "Thread creation failed");
        free(info);
      } else {
        pthread_detach(tid);
        LOG_INFO(server, "Client[%d] thread started.", client_id);
      }
    } else {
      pthread_mutex_unlock(&accepted_sockets_mutex);
      tls_cleanup(ssl);
      close(client_fd);
      free(info);
    }
  }
}

/* --- Main --- */

int main(void) {
  signal(SIGINT, interrupt_handler);

  int server_socket = createTCPIp4Socket();
  g_server_socket_fd = server_socket;

  struct sockaddr_in *server_address = createIPv4Address("127.0.0.1", PORT);
  server_bind(server_socket, (struct sockaddr *)server_address);
  server_listen(server_socket);
  socket_list_init();

  /* TLS context */
  SSL_CTX *tls_ctx = create_server_tls_context(CERT_PATH, KEY_PATH);
  if (!tls_ctx) {
    LOG_ERROR(server, "Failed to create TLS context. Run gen_certs.sh first!");
    exit(EXIT_FAILURE);
  }

  LOG_SUCCESS(server, "=== n0cryp2 Server (TLS 1.3 + E2E) ===");
  LOG_INFO(server, "Server is RELAY-ONLY: cannot read E2E encrypted messages.");
  start_accept_connections(server_socket, tls_ctx);

  SSL_CTX_free(tls_ctx);
  shutdown(server_socket, SHUT_RDWR);
  return 0;
}