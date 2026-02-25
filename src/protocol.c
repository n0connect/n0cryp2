#include "protocol.h"
#include "logmacro.h"
#include <arpa/inet.h> /* htons/ntohs */
#include <stdlib.h>
#include <string.h>

/* Read exactly n bytes from SSL */
static int ssl_read_exact(SSL *ssl, void *buf, int n) {
  int total = 0;
  while (total < n) {
    int r = SSL_read(ssl, (uint8_t *)buf + total, n - total);
    if (r <= 0)
      return -1;
    total += r;
  }
  return 0;
}

/* Write exactly n bytes to SSL */
static int ssl_write_exact(SSL *ssl, const void *buf, int n) {
  int total = 0;
  while (total < n) {
    int w = SSL_write(ssl, (const uint8_t *)buf + total, n - total);
    if (w <= 0)
      return -1;
    total += w;
  }
  return 0;
}

int protocol_send(SSL *ssl, uint8_t type, const void *payload, uint16_t len) {
  if (len > MAX_PAYLOAD_SIZE) {
    LOG_ERROR(rsa, "Payload too large: %u", len);
    return -1;
  }

  /* Header: [type(1)] [len(2 BE)] */
  uint8_t header[3];
  header[0] = type;
  uint16_t net_len = htons(len);
  memcpy(&header[1], &net_len, 2);

  if (ssl_write_exact(ssl, header, 3) < 0)
    return -1;
  if (len > 0 && payload) {
    if (ssl_write_exact(ssl, payload, len) < 0)
      return -1;
  }
  return 0;
}

int protocol_recv(SSL *ssl, uint8_t *type_out, uint8_t **payload_out,
                  uint16_t *len_out) {
  uint8_t header[3];
  if (ssl_read_exact(ssl, header, 3) < 0)
    return -1;

  *type_out = header[0];
  uint16_t net_len;
  memcpy(&net_len, &header[1], 2);
  *len_out = ntohs(net_len);

  if (*len_out > MAX_PAYLOAD_SIZE) {
    LOG_ERROR(rsa, "Received payload too large: %u", *len_out);
    return -1;
  }

  if (*len_out == 0) {
    *payload_out = NULL;
    return 0;
  }

  *payload_out = (uint8_t *)malloc(*len_out);
  if (!*payload_out)
    return -1;

  if (ssl_read_exact(ssl, *payload_out, *len_out) < 0) {
    free(*payload_out);
    *payload_out = NULL;
    return -1;
  }

  return 0;
}
