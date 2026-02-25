/* SOCKET PROGRAMMING "SOCKET_HEADER" */
#ifndef SOCKETUTIL_SOCKETUTIL_H
#define SOCKETUTIL_SOCKETUTIL_H

/* (#12) Sadece gerekli sistem başlıkları — colorcodes/logmacro kaldırıldı */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

int createTCPIp4Socket();
struct sockaddr_in *createIPv4Address(const char *ip_address,
                                      unsigned short int port);

#endif /* SOCKETUTIL_SOCKETUTIL_H */