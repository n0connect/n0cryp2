#ifndef TCPCLIENT_H
#define TCPCLIENT_H

#include <stdbool.h> /* (#22) stdbool en üste taşındı */

#include "clientkey.h"
#include "colorcodes.h"
#include "cryp2.h"
#include "logmacro.h"
#include "socketutil.h"
#include "strtohex.h"

#define PORT 2000
/* (#20) MAX_CLIENTS kaldırıldı — client'ta gereksiz, sadece buffer hesabı için
 * tutuldu */
#define MAX_CLIENTS 10
/* (#21) MAX_SEND kaldırıldı — hiçbir yerde kullanılmıyor */
#define BUFFER_SIZE 256

/* Server address (extern declaration — definition TCPClient.c'de) */
extern const char *address;

void newline_messagebox();
void messagebox();
int get_terminal_width();
int get_terminal_height();
void start_listening_messages_new_thread(int network_socket);
/* (#23) listening_messages_thread kaldırıldı — tanımsız eski deklarasyon */

char *get_username();
char *get_password();

/* (#24) connect_the_adress — typo korundu (sonra rename edilebilir) */
bool connect_the_adress(int network_socket, struct sockaddr *server_address);
bool send_the_buffer(int network_socket, char *buffer);
bool send_secure(int network_socket, const char *buffer);

/* Encrypted communication */
void encryped_user_login(int network_socket, struct sockaddr *server_address);
void secure_user_send_message(int network_socket,
                              struct sockaddr *server_address, char *username);
void *secure_listening_messages_thread(void *arg);

#endif /* TCPCLIENT_H */