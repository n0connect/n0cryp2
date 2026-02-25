#ifndef TCPSERVER_H
#define TCPSERVER_H

#include "colorcodes.h"
#include "database.h"
#include "logmacro.h"
#include "socketutil.h"

#include "cryp2.h"
#include "serverkey.h"
#include "strtohex.h"

struct AcceptedSocket {
  int accepted_socket_fd;
  struct sockaddr_in address;
  int error;
  bool accepted_success;
};

#define PORT 2000
#define QUEUE 5
#define MAX_CLIENTS 10 // Max 10 Client
#define BUFFER_SIZE 256

// ------------------------------- //
// Global değişkenler (extern declaration — definition TCPServer.c'de)
extern struct AcceptedSocket *accepted_sockets;
extern unsigned int accepted_sockets_count;

extern void *server_address_ptr;

// Create Global Client ID counter
extern int global_client_id;
extern pthread_mutex_t id_mutex;

// Mutex to protect access to the accepted_sockets array
extern pthread_mutex_t accepted_sockets_mutex;

void interrupt_handler(int sig);
struct AcceptedSocket *AcceptIncomingConnections(int server_socket);
void handle_client_communication(int client_socket_fd, int sthread_id);
void *recv_the_client(void *arg);
void recv_the_client_separate_threads(struct AcceptedSocket *client_socket);
void start_accept_connections(int server_socket);
void send_the_buffer_other_clients(int client_socket, char *buffer);
void __arg_options(int argc, char **argv);
int generate_client_id();

void socket_list_allocate();
void server_listen(int server_socket);
void server_bind(int server_socket, struct sockaddr *server_address);

bool secure_handle_login(int client_socket_fd, int sthread_id);
void secure_handle_client_communication(int client_socket_fd, int sthread_id);

//
void secure_send_the_buffer_other_clients(int client_socket, char *buffer);

#endif

/**
 * @brief  handle_client_communication need to be encrypted
 *
 */