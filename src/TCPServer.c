// SOCKET PROGRAMMING "TCP_SERVER" //
// -----------------------------  //
/**
 * @file TCPServer.c
 * @author Ahmet Berat (niceshotfree@gmail.com)
 * @brief
 * @version 0.1
 * @date 2024-11-25
 *
 * @copyright Copyright (c) 2024
 *
 */
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <string.h>

#include "tcpserver.h"

#define PUBLIC_KEY getPublicKeyPath()
#define PRIVATE_KEY getPrivateKeyPath()

/* Global değişken tanımları */
struct AcceptedSocket *accepted_sockets = NULL;
unsigned int accepted_sockets_count = 0;
int global_client_id = 0;
pthread_mutex_t id_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t accepted_sockets_mutex = PTHREAD_MUTEX_INITIALIZER;

/* (#42) interrupt handler için server_socket_fd global — doğru fd */
static int g_server_socket_fd = -1;

/**
 * @brief Handle the CTRL+C Signal
 * (#43) Sadece async-signal-safe fonksiyonlar kullanılıyor
 * (#42) server_address_ptr cast hatası giderildi
 */
void interrupt_handler(int sig) {
  (void)sig;
  /* async-signal-safe: write, shutdown, _exit */
  const char msg[] = "\n[SIGNAL] Shutting down server...\n";
  write(STDERR_FILENO, msg, sizeof(msg) - 1);

  if (g_server_socket_fd >= 0) {
    shutdown(g_server_socket_fd, SHUT_RDWR);
    close(g_server_socket_fd);
  }
  _exit(EXIT_SUCCESS);
}

/**
 * @brief Bind server socket
 */
void server_bind(int server_socket, struct sockaddr *server_address) {
  if (bind(server_socket, server_address, sizeof(struct sockaddr_in)) < 0) {
    shutdown(server_socket, SHUT_RDWR);
    free(server_address);
    LOG_ERROR(server, "Server bind error");
    exit(EXIT_FAILURE);
  } else {
    LOG_SUCCESS(server, "Connection successfully.");
  }
}

/**
 * @brief Start Listen the current socket with a limit
 */
void server_listen(int server_socket) {
  if (listen(server_socket, QUEUE) < 0) {
    LOG_ERROR(server, "Listening error");
    exit(EXIT_FAILURE);
  } else {
    LOG_INFO(server, "Listening the requests...");
  }
}

/**
 * @brief Allocate socket list
 */
void socket_list_allocate() {
  accepted_sockets = (struct AcceptedSocket *)calloc(
      MAX_CLIENTS, sizeof(struct AcceptedSocket));
  if (accepted_sockets == NULL) {
    LOG_ERROR(server, "Socket List Allocate Error");
    exit(EXIT_FAILURE);
  }
}

/**
 * @brief Generate unique client ID (thread-safe)
 */
int generate_client_id() {
  pthread_mutex_lock(&id_mutex);
  int new_id = global_client_id++;
  pthread_mutex_unlock(&id_mutex);
  return new_id;
}

/**
 * @brief Accept incoming client connection
 */
struct AcceptedSocket *AcceptIncomingConnections(int server_socket) {
  struct sockaddr_in client_address;
  socklen_t client_address_size = sizeof(client_address);

  int client_socket = accept(server_socket, (struct sockaddr *)&client_address,
                             &client_address_size);

  struct AcceptedSocket *accepted_return =
      (struct AcceptedSocket *)malloc(sizeof(struct AcceptedSocket));

  if (accepted_return == NULL) {
    LOG_ERROR(server, "Memory allocation for AcceptedSocket failed");
    exit(EXIT_FAILURE);
  }

  accepted_return->accepted_socket_fd = client_socket;
  accepted_return->address = client_address;

  if (client_socket < 0) {
    accepted_return->accepted_success = false;
    accepted_return->error = client_socket;
    LOG_ERROR(server, "Accept error: %s", strerror(errno));
  } else {
    accepted_return->accepted_success = true;
    accepted_return->error = 0;
    LOG_SUCCESS(server, "Client connected successfully.");
  }

  return accepted_return;
}

/* (#44) send_the_buffer_other_clients kaldırıldı — dead code, sadece secure_
 * versiyonu var */

/**
 * @brief Thread function for client handling
 */
void *recv_the_client(void *arg) {
  struct AcceptedSocket *client_socket = (struct AcceptedSocket *)arg;
  int client_socket_fd = client_socket->accepted_socket_fd;

  int client_id = generate_client_id();

  if (!secure_handle_login(client_socket_fd, client_id)) {
    LOG_ERROR(server, "Client[%d] failed to login. Shutting down connection",
              client_id);
    close(client_socket_fd);
    free(client_socket);

    pthread_mutex_lock(&accepted_sockets_mutex);
    for (size_t i = 0; i < accepted_sockets_count; i++) {
      if (accepted_sockets[i].accepted_socket_fd == client_socket_fd) {
        for (size_t j = i; j < accepted_sockets_count - 1; j++) {
          accepted_sockets[j] = accepted_sockets[j + 1];
        }
        accepted_sockets_count--;
        break;
      }
    }
    pthread_mutex_unlock(&accepted_sockets_mutex);
    return NULL;
  } else {
    LOG_SUCCESS(server, "Receiving messages and starting communication");
  }

  secure_handle_client_communication(client_socket_fd, client_id);

  /* Remove client from list */
  pthread_mutex_lock(&accepted_sockets_mutex);
  for (size_t i = 0; i < accepted_sockets_count; i++) {
    if (accepted_sockets[i].accepted_socket_fd == client_socket_fd) {
      close(client_socket_fd);
      for (size_t j = i; j < accepted_sockets_count - 1; j++) {
        accepted_sockets[j] = accepted_sockets[j + 1];
      }
      accepted_sockets_count--;
      break;
    }
  }
  pthread_mutex_unlock(&accepted_sockets_mutex);

  free(client_socket);
  return NULL;
}

/**
 * @brief Create thread for client
 */
void recv_the_client_separate_threads(struct AcceptedSocket *client_socket) {
  pthread_t sthread_id;

  if (pthread_create(&sthread_id, NULL, recv_the_client, client_socket) != 0) {
    LOG_ERROR(server, "Failed to create client thread");
    free(client_socket);
    exit(EXIT_FAILURE);
  }

  if (pthread_detach(sthread_id) != 0) {
    LOG_ERROR(server, "Failed to detach client thread");
    exit(EXIT_FAILURE);
  }

  LOG_INFO(server, "Thread created and detached successfully for client.");
}

/**
 * @brief Accept connections loop
 */
void start_accept_connections(int server_socket) {
  while (true) {
    /* (#45) mutex ile koruma — race condition giderildi */
    pthread_mutex_lock(&accepted_sockets_mutex);
    unsigned int current_count = accepted_sockets_count;
    pthread_mutex_unlock(&accepted_sockets_mutex);

    if (current_count >= MAX_CLIENTS) {
      LOG_ERROR(
          server,
          "Maximum number of clients reached. Rejecting new connections.");
      sleep(1);
      continue;
    }

    struct AcceptedSocket *client_socket =
        AcceptIncomingConnections(server_socket);

    /* (#46) accept fail durumunda client_socket free ediliyor */
    if (!client_socket->accepted_success) {
      LOG_ERROR(server, "Incoming connection failed.");
      free(client_socket);
      continue;
    }

    pthread_mutex_lock(&accepted_sockets_mutex);
    if (accepted_sockets_count < MAX_CLIENTS) {
      accepted_sockets[accepted_sockets_count++] = *client_socket;
      pthread_mutex_unlock(&accepted_sockets_mutex);
      recv_the_client_separate_threads(client_socket);
    } else {
      pthread_mutex_unlock(&accepted_sockets_mutex);
      shutdown(client_socket->accepted_socket_fd, SHUT_RDWR);
      free(client_socket);
    }
  }
}

int main(int argc, char **argv) {
  (void)argc;
  (void)argv;

  signal(SIGINT, interrupt_handler);

  int server_socket = createTCPIp4Socket();
  g_server_socket_fd = server_socket; /* (#42) signal handler için */

  /* (#47) const char* kullanılıyor */
  const char *address = "127.0.0.1";
  struct sockaddr_in *server_address = createIPv4Address(address, PORT);

  server_bind(server_socket, (struct sockaddr *)server_address);
  server_listen(server_socket);
  socket_list_allocate();
  start_accept_connections(server_socket);

  shutdown(server_socket, SHUT_RDWR);
  exit(EXIT_SUCCESS);
}

/**
 * @brief Secure login handler
 */
bool secure_handle_login(int client_socket_fd, int sthread_id) {
  LOG_INFO(server, "Secure Handle Login.");
  bool login_successful = false;

  while (!login_successful) {
    char buffer[BUFFER_SIZE];

    ssize_t amount_received = recv(client_socket_fd, buffer, BUFFER_SIZE, 0);
    if (amount_received <= 0) {
      LOG_ERROR(server, "Recv the data error. (%zd)", amount_received);
      return false;
    } else {
      /* (#48) sadece amount_received kadar hex'e çevir */
      char *hex_ret = str_to_hex(buffer, (size_t)amount_received);
      LOG_SUCCESS(server, "Succes Recv data. (%zd)", amount_received);
      LOG_SUCCESS(server, "Data (Hex): %s", hex_ret);
      free(hex_ret);
    }

    /* (#49) RSA key leak giderildi — key ayrı yükleniyor ve free ediliyor */
    LOG_INFO(server, "Start Decrypt message.");
    RSA *priv_key = load_private_key(PRIVATE_KEY);
    int rsa_sz = RSA_size(priv_key);
    RSA_free(priv_key);
    char *decrypted_msg = decrypt_message(buffer, rsa_sz, PRIVATE_KEY);
    LOG_INFO(server, "Decrypted message: %s", decrypted_msg);
    LOG_INFO(server, "Decrypted message length: %zu", strlen(decrypted_msg));

    strncpy(buffer, decrypted_msg, BUFFER_SIZE - 1);
    buffer[BUFFER_SIZE - 1] = '\0';
    free(decrypted_msg);
    LOG_INFO(server, "Client[%d] sent login credentials: %s", sthread_id,
             buffer);

    char username[32];
    char password[64];

    /* (#50) sscanf dönüş değeri kontrol ediliyor */
    int parsed = sscanf(buffer, "%31[^:]:%63[^\n]", username, password);
    if (parsed != 2) {
      LOG_ERROR(server, "Failed to parse login credentials.");
      const char *fail_message = "Invalid credential format";
      char *secure_enc = encrypt_message(fail_message, PUBLIC_KEY);
      send(client_socket_fd, secure_enc, BUFFER_SIZE, 0);
      free(secure_enc);
      continue;
    }

    if (check_credentials(username, password)) {
      const char *success_message = "Login:Successfully";
      char *secure_enc = encrypt_message(success_message, PUBLIC_KEY);
      ssize_t send_amount = send(client_socket_fd, secure_enc, BUFFER_SIZE, 0);

      if (send_amount < 0) {
        LOG_ERROR(server, "Login success but data cannot sending.");
      } else {
        LOG_SUCCESS(server, "Login success and data sent to client.");
        LOG_INFO(server, "Data Size: [%zd]", send_amount);
      }
      free(secure_enc);
      login_successful = true;
    } else {
      const char *fail_message = "Username or Password not correct, try again";
      char *secure_enc = encrypt_message(fail_message, PUBLIC_KEY);
      ssize_t send_amount = send(client_socket_fd, secure_enc, BUFFER_SIZE, 0);

      if (send_amount < 0) {
        LOG_ERROR(server, "Login failed and data cannot sending.");
      } else {
        LOG_INFO(server, "Login failed and data sent to client.");
        LOG_INFO(server, "Data Size: [%zd]", send_amount);
      }
      free(secure_enc);
    }
  }

  return true;
}

/**
 * @brief Handle client communication (encrypted)
 */
void secure_handle_client_communication(int client_socket_fd, int sthread_id) {
  char buffer[BUFFER_SIZE];
  while (true) {
    ssize_t amount_received = recv(client_socket_fd, buffer, BUFFER_SIZE, 0);
    if (amount_received <= 0) {
      LOG_ERROR(server, "Client disconnected or receive error.");
      return;
    } else {
      LOG_INFO(server, "Received Data Size: %zd", amount_received);
    }

    /* (#51) RSA key leak giderildi */
    RSA *priv_key = load_private_key(PRIVATE_KEY);
    int rsa_sz = RSA_size(priv_key);
    RSA_free(priv_key);
    char *decrypted_recv = decrypt_message(buffer, rsa_sz, PRIVATE_KEY);
    LOG_SUCCESS(server, "Decrypted Buffer: %s", decrypted_recv);
    LOG_SUCCESS(server, "Decrypted Buffer Length: %zu", strlen(decrypted_recv));
    LOG_INFO(server, "Client[%d]: %s", sthread_id, decrypted_recv);

    free(decrypted_recv);

    secure_send_the_buffer_other_clients(client_socket_fd, buffer);
  }
}

/**
 * @brief Send encrypted buffer to other clients
 */
void secure_send_the_buffer_other_clients(int client_socket, char *buffer) {
  pthread_mutex_lock(&accepted_sockets_mutex);
  for (size_t i = 0; i < accepted_sockets_count; i++) {
    if (accepted_sockets[i].accepted_socket_fd != client_socket) {
      ssize_t send_result =
          send(accepted_sockets[i].accepted_socket_fd, buffer, BUFFER_SIZE, 0);

      if (send_result < 0) {
        LOG_ERROR(server, "Message send error (Client[%d])",
                  accepted_sockets[i].accepted_socket_fd % 11);
      } else {
        LOG_SUCCESS(server, "Message sent successfully. (Client[%d])",
                    accepted_sockets[i].accepted_socket_fd % 11);
      }
    }
  }
  pthread_mutex_unlock(&accepted_sockets_mutex);
}

// TCP_SERVER