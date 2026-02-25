/* SOCKET PROGRAMMING "SOCKET_UTIL" */
/**
 * @file socketutil.c
 * @author Ahmet Berat (niceshotfree@gmail.com)
 * @brief
 * @version 0.1
 * @date 2024-11-25
 *
 * @copyright Copyright (c) 2024
 *
 */
#include "socketutil.h"
#include "colorcodes.h"
#include "logmacro.h"

int createTCPIp4Socket() {
  /* AF_INET: IPV4, SOCK_STREAM: TCP, PROTOCOL: 0 */
  int socket_return = socket(AF_INET, SOCK_STREAM, 0);

  if (socket_return < 0) {
    LOG_ERROR(auth, "Socket error.");
    exit(EXIT_FAILURE);
  } else {
    LOG_SUCCESS(auth, "Socket created succesfully.");
  }

  return socket_return;
}

struct sockaddr_in *createIPv4Address(const char *ip_address,
                                      unsigned short int port) {
  /* (#25) malloc NULL kontrolü eklendi */
  struct sockaddr_in *address =
      (struct sockaddr_in *)calloc(1, sizeof(struct sockaddr_in));
  /* (#26) calloc kullanarak sıfırlanmış bellek (memset gereksiz) */

  if (address == NULL) {
    LOG_ERROR(auth, "Failed to allocate memory for address.");
    exit(EXIT_FAILURE);
  }

  address->sin_family = AF_INET;
  address->sin_port = htons(port);

  /* (#27) NULL kontrolü eklendi */
  if (ip_address == NULL || strlen(ip_address) == 0) {
    address->sin_addr.s_addr = INADDR_ANY;
  } else {
    /* (#28) inet_pton dönüş değeri kontrol ediliyor */
    int pton_result = inet_pton(AF_INET, ip_address, &(address->sin_addr));
    if (pton_result <= 0) {
      LOG_ERROR(auth, "Invalid IP address format: %s", ip_address);
      free(address);
      exit(EXIT_FAILURE);
    }
  }

  return address;
}
