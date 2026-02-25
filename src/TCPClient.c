// SOCKET PROGRAMMING "TCP_CLIENT" //
// -----------------------------  //
/**
 * @file TCPClient.c
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
#include <stdbool.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "tcpclient.h"

#define PUBLIC_KEY getPublicKeyPath()
#define PRIVATE_KEY getPrivateKeyPath()
#define MAX_CHAR_LIMIT 256

/* B4: address definition */
const char *address = "127.0.0.1";

char *username_ptr = NULL;

/**
 * @brief Adds a newline and logs the current user's online status.
 */
void newline_messagebox() {
  fprintf(stdout, "\n");
  if (username_ptr) {
    LOG_MSG(username_ptr, online);
  } else {
    LOG_MSG("unknown", online);
  }
  fflush(stdout);
}

/**
 * @brief Logs the current user's online status.
 */
void messagebox() {
  if (username_ptr) {
    LOG_MSG(username_ptr, online);
  } else {
    LOG_MSG("unknown", online);
  }
  fflush(stdout);
}

/**
 * @brief Get the width of the terminal.
 */
int get_terminal_width() {
  struct winsize ws;
  if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) != -1) {
    return ws.ws_col;
  }
  return 80;
}

/**
 * @brief Get the height of the terminal.
 */
int get_terminal_height() {
  struct winsize ws;
  if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) != -1) {
    return ws.ws_row;
  }
  return 20;
}

/**
 * @brief Create new thread for listening to messages.
 */
void start_listening_messages_new_thread(int network_socket) {
  pthread_t thread_id;

  /* (#52) malloc NULL kontrolü eklendi */
  int *socket_copy = (int *)malloc(sizeof(int));
  if (socket_copy == NULL) {
    LOG_ERROR(client, "Failed to allocate memory for socket copy");
    exit(EXIT_FAILURE);
  }
  *socket_copy = network_socket;

  int thread_result = pthread_create(
      &thread_id, NULL, secure_listening_messages_thread, socket_copy);

  if (thread_result != 0) {
    LOG_ERROR(client, "Failed to create thread");
    free(socket_copy);
    exit(EXIT_FAILURE);
  }
  pthread_detach(thread_id);
}

/**
 * @brief Connect to server address
 * (#53) sizeof(struct sockaddr_in) kullanılıyor
 */
bool connect_the_adress(int network_socket, struct sockaddr *server_address) {
  if (connect(network_socket, server_address, sizeof(struct sockaddr_in)) < 0) {
    LOG_ERROR(client, "Connection error.");
    shutdown(network_socket, SHUT_RDWR);
    free(server_address);
    return false;
  }

  LOG_SUCCESS(client, "Connection successfully.");
  return true;
}

/**
 * @brief Get the username
 */
char *get_username() {
  char *username = NULL;
  size_t username_size = 0;

  if (username_ptr == NULL) {
    username_ptr = (char *)malloc(32 * sizeof(char));
    if (username_ptr == NULL) {
      LOG_ERROR(client, "Failed to allocate memory for username_ptr");
      exit(EXIT_FAILURE);
    }
  }

  while (true) {
    /* (#54) RESET eklendi — color bleed giderildi */
    fprintf(stdout, BCYN "  - Please enter your username: " RESET);
    fflush(stdout);
    getline(&username, &username_size, stdin);
    if (username == NULL) {
      LOG_ERROR(client, "Failed to read username");
      exit(EXIT_FAILURE);
    }
    username[strcspn(username, "\n")] = '\0';
    if (strlen(username) > 3 && strlen(username) <= 31) {
      strncpy(username_ptr, username, 31);
      username_ptr[31] = '\0';
      free(username);
      break;
    } else {
      LOG_ERROR(client, "Username must be between 4 and 31 characters");
      sleep(3);
      free(username);
      username = NULL;
      username_size = 0;
      fprintf(stdout, "\033[2J\033[H");
      fflush(stdout);
    }
  }

  fprintf(stdout, "\033[2J\033[H");
  fflush(stdout);
  return username_ptr;
}

/**
 * @brief Get the password
 * (#55) newline stripping burada yapılıyor, strlen kontrolü düzeltildi
 */
char *get_password() {
  char *password = NULL;
  size_t password_size = 0;

  while (true) {
    /* (#54) RESET eklendi */
    fprintf(stdout, BCYN "  - Please enter your password: " RESET);
    fflush(stdout);
    getline(&password, &password_size, stdin);
    if (password == NULL) {
      LOG_ERROR(client, "Failed to read password");
      exit(EXIT_FAILURE);
    }

    /* (#55) Newline'ı burada kaldır, sonra uzunluk ölç */
    password[strcspn(password, "\n")] = '\0';
    size_t pw_len = strlen(password);

    if (pw_len >= 3 && pw_len <= 64) {
      break;
    } else {
      LOG_ERROR(client, "Password must be between 3 and 64 characters");
      sleep(3);
      free(password);
      password = NULL;
      password_size = 0;
      fprintf(stdout, "\033[2J\033[H");
      fflush(stdout);
    }
  }

  fprintf(stdout, "\033[2J\033[H");
  fflush(stdout);
  return password;
}

/**
 * @brief Send buffer to network socket
 */
bool send_the_buffer(int network_socket, char *buffer) {
  if (buffer == NULL || strlen(buffer) == 0) {
    LOG_ERROR(client, "Invalid buffer.");
    return false;
  }

  ssize_t amount_was_sent = send(network_socket, buffer, strlen(buffer), 0);
  if (amount_was_sent < 0) {
    LOG_ERROR(client, "Error sending message.");
    return false;
  }

  return true;
}

/**
 * @brief Send encrypted buffer to network socket
 * (#56) strlen kontrolü kaldırıldı — ciphertext'te NULL byte olabilir
 */
bool send_secure(int network_socket, const char *buffer) {
  if (buffer == NULL) {
    LOG_ERROR(client, "Invalid buffer.");
    return false;
  }

  ssize_t amount_was_sent = send(network_socket, buffer, BUFFER_SIZE, 0);
  if (amount_was_sent < 0) {
    LOG_ERROR(client, "Error sending message.");
    return false;
  }

  newline_messagebox();
  return true;
}

int main() {
  int network_socket = createTCPIp4Socket();
  struct sockaddr_in *server_address = createIPv4Address(address, PORT);
  bool connection_status =
      connect_the_adress(network_socket, (struct sockaddr *)server_address);

  if (!connection_status) {
    exit(EXIT_FAILURE);
  }

  encryped_user_login(network_socket, (struct sockaddr *)server_address);
  start_listening_messages_new_thread(network_socket);
  secure_user_send_message(network_socket, (struct sockaddr *)server_address,
                           username_ptr);

  shutdown(network_socket, SHUT_RDWR);
  free(server_address);
  exit(EXIT_SUCCESS);
}

/**
 * @brief Encrypted user login
 */
void encryped_user_login(int network_socket, struct sockaddr *server_address) {
  (void)server_address;

  bool login_successful = false;

  while (!login_successful) {
    char *username = NULL, *password = NULL;
    char buffer[BUFFER_SIZE];
    char secure_recv[BUFFER_SIZE];

    username = get_username();
    /* (#57) username zaten get_username()'de trim edildi — gereksiz strcspn
     * kaldırıldı */
    password = get_password();
    /* (#55) password artık get_password()'da trim ediliyor — burada da gereksiz
     */

    int sn_ret = snprintf(buffer, sizeof(buffer), "%s:%s", username, password);
    if (sn_ret < 0 || (size_t)sn_ret >= sizeof(buffer)) {
      LOG_ERROR(client, "Buffer overflow in user login.");
      free(password);
      exit(EXIT_FAILURE);
    }

    char *secure_enc = encrypt_message(buffer, PUBLIC_KEY);
    if (!secure_enc) {
      LOG_ERROR(client, "Encryption failed.");
      free(password);
      exit(EXIT_FAILURE);
    } else {
      char *hex_ret = str_to_hex(secure_enc, BUFFER_SIZE);
      LOG_SUCCESS(client, "Encrypted message       : %s", hex_ret);
      LOG_SUCCESS(client, "Encrypted message length: %zu", strlen(secure_enc));
      free(hex_ret);
    }

    /* (#58) Double free giderildi — hata dalında free yok, sadece sonda */
    if (send(network_socket, secure_enc, BUFFER_SIZE, 0) < 0) {
      LOG_ERROR(client, "Failed to send encrypted login data.");
      free(secure_enc);
      free(password);
      exit(EXIT_FAILURE);
    } else {
      LOG_SUCCESS(client, "Success send encrypted login data");
    }
    free(secure_enc);
    secure_enc = NULL; /* dangling pointer koruması */

    LOG_SUCCESS(client, "Recv the data from server");
    ssize_t amount_received = recv(network_socket, secure_recv, BUFFER_SIZE, 0);
    if (amount_received <= 0) {
      LOG_ERROR(client, "Failed to receive server response.");
      free(password);
      exit(EXIT_FAILURE);
    } else {
      char *hex_ret = str_to_hex(secure_recv, (size_t)amount_received);
      LOG_SUCCESS(client, "Received Data Size  : %zd", amount_received);
      LOG_SUCCESS(client, "Secure Buffer (hex) : %s", hex_ret);
      free(hex_ret);
    }

    /* (#59) RSA key leak giderildi */
    RSA *priv_key = load_private_key(PRIVATE_KEY);
    int rsa_sz = RSA_size(priv_key);
    RSA_free(priv_key);
    char *decrypted_recv = decrypt_message(secure_recv, rsa_sz, PRIVATE_KEY);

    LOG_SUCCESS(client, "Decrypted Buffer       : %s", decrypted_recv);
    LOG_SUCCESS(client, "Decrypted Buffer Length: %zu", strlen(decrypted_recv));

    const char *success_message = "Login:Successfully";
    if (strncmp(decrypted_recv, success_message, strlen(success_message)) ==
        0) {
      LOG_SUCCESS(client, "Login successful.");
      login_successful = true;
    } else {
      LOG_INFO(client, "Login failed: %s", decrypted_recv);
    }
    free(decrypted_recv);
    free(password);
  }
}

/**
 * @brief Send messages to server (user input loop)
 */
void secure_user_send_message(int network_socket,
                              struct sockaddr *server_address, char *username) {
  (void)server_address;
  char *terminal_line = NULL;
  size_t terminal_line_size = 0;
  char stack_buffer[BUFFER_SIZE];
  bool max_length_err = false;
  unsigned int err_count = 0;

  newline_messagebox();

  while (true) {
    if (terminal_line != NULL) {
      free(terminal_line);
    }
    terminal_line = NULL;
    terminal_line_size = 0;

    printf("\033[s");
    ssize_t return_char_count =
        getline(&terminal_line, &terminal_line_size, stdin);

    if (return_char_count == -1) {
      LOG_ERROR(client, "Terminal line error [%u]", err_count);
      err_count++;
      continue;
    } else if (return_char_count == 1 && terminal_line[0] == '\n') {
      printf("\033[K");
      printf("\033[u");
      printf("\033[K");
      printf("\r");
      messagebox();
      fflush(stdout);
      continue;
    }

    /* (#60) MAX_CHAR_LIMIT makrosu kullanılıyor */
    if ((size_t)MAX_CHAR_LIMIT < strlen(terminal_line)) {
      max_length_err = true;
      printf("\033[s");
      int terminal_height = get_terminal_height();
      printf("\033[%d;1H", terminal_height);
      printf(RESET BLKHB HWHT
             "Error: Max character size is %d (Current: %zu)" RESET,
             MAX_CHAR_LIMIT, strlen(terminal_line));
      printf("\033[u");
      fflush(stdout);
      continue;
    } else if (max_length_err) {
      max_length_err = false;
      printf("\033[s");
      int terminal_height = get_terminal_height();
      printf("\033[%d;1H", terminal_height);
      printf("\033[K");
      printf("\033[u");
      fflush(stdout);
    }

    terminal_line[strcspn(terminal_line, "\n")] = '\0';
    if (strcmp(terminal_line, "/exit") == 0 ||
        strcmp(terminal_line, "/quit") == 0) {
      break;
    }

    snprintf(stack_buffer, sizeof(stack_buffer), "%s: %s", username,
             terminal_line);

    char *return_encryption = encrypt_message(stack_buffer, PUBLIC_KEY);
    if (!return_encryption) {
      LOG_ERROR(client, "Encryption failed.");
      exit(EXIT_FAILURE);
    } else {
      LOG_SUCCESS(client, "Encrypted message length: %d", BUFFER_SIZE);
    }

    if (send_secure(network_socket, return_encryption)) {
      LOG_SUCCESS(client, "Encrypted message sent to server successfully.");
    }
    free(return_encryption);
  }

  if (terminal_line != NULL) {
    free(terminal_line);
  }
}

/**
 * @brief Listen for incoming messages from server (thread)
 */
void *secure_listening_messages_thread(void *arg) {
  int network_socket = *(int *)arg;
  free(arg);

  /* (#61) buffer boyutu sadece BUFFER_SIZE — gereksiz büyük alloc giderildi */
  char buffer[BUFFER_SIZE];

  int terminal_width = get_terminal_width();
  size_t half_terminal_width = (size_t)terminal_width / 2;

  while (true) {
    ssize_t amount_received = recv(network_socket, buffer, BUFFER_SIZE, 0);
    if (amount_received <= 0) {
      if (amount_received == 0) {
        LOG_ERROR(client, "Connection closed by server");
      } else {
        LOG_ERROR(client, "Message receive error");
      }
      break;
    }

    LOG_INFO(client, "Decryption is start");

    /* (#62) RSA key leak giderildi */
    RSA *priv_key = load_private_key(PRIVATE_KEY);
    int rsa_sz = RSA_size(priv_key);
    RSA_free(priv_key);
    char *decrypted_buffer = decrypt_message(buffer, rsa_sz, PRIVATE_KEY);

    strncpy(buffer, decrypted_buffer, BUFFER_SIZE - 1);
    buffer[BUFFER_SIZE - 1] = '\0';
    LOG_INFO(client, "Decrypted Buffer: %s", decrypted_buffer);
    LOG_INFO(client, "Decrypted Buffer Length: %zu", strlen(decrypted_buffer));
    free(decrypted_buffer);

    size_t message_length = strlen(buffer);

    char temp_username[32];
    char temp_buffer[1024];

    /* (#63) sscanf dönüş değeri kontrol ediliyor */
    int parsed =
        sscanf(buffer, "%31[^:]:%1023[^\n]", temp_username, temp_buffer);
    if (parsed < 2) {
      /* Mesaj formatı beklenen değilse doğrudan yazdır */
      fprintf(stdout, "\r" BCYN "%s" RESET "\n", buffer);
      fflush(stdout);
      newline_messagebox();
      continue;
    }

    size_t username_len = strlen(temp_username);

    /* (#64) unsigned underflow koruması */
    if (message_length > username_len) {
      message_length -= username_len;
    } else {
      message_length = 0;
    }

    fprintf(stdout, "\r");

    if (half_terminal_width < message_length) {
      size_t start_index = 0;
      size_t remaining_length = message_length;
      fprintf(stdout, BCYN "%*s-[%s]:", (int)half_terminal_width, "",
              temp_username);
      while (remaining_length > 0) {
        size_t line_length = remaining_length > half_terminal_width
                                 ? half_terminal_width
                                 : remaining_length;
        fprintf(stdout, "\n");
        fprintf(stdout, BCYN "%*s", (int)half_terminal_width, "");
        fwrite(temp_buffer + start_index, 1, line_length, stdout);
        remaining_length -= line_length;
        start_index += line_length;
      }
    } else {
      fprintf(stdout, BCYN "%*s%s" RESET "\n", (int)half_terminal_width, "",
              buffer);
    }
    fflush(stdout);
    newline_messagebox();
  }

  return NULL;
}

// TCP_CLIENT