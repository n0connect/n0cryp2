#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <openssl/ssl.h>
#include <stdint.h>

/* Message types */
#define MSG_LOGIN_REQ 0x01 /* C→S: "username:password" */
#define MSG_LOGIN_RES 0x02 /* S→C: [uint8 ok][int32 client_id] */
#define MSG_PUB_KEY 0x03   /* Both: [int32 client_id][32B pubkey] */
#define MSG_KEY_LIST 0x04  /* S→C: [int32 count][{int32 id, 32B key} × N] */
#define MSG_E2E_MSG 0x05   /* Both: [int32 id][12B nonce][ciphertext+16B tag] */
#define MSG_CLIENT_LEFT 0x06 /* S→C: [int32 client_id] */

#define MAX_PAYLOAD_SIZE 4096

/*
 * Wire format: [uint8 type][uint16 payload_len BE][payload]
 * Header = 3 bytes
 */

/* Send a framed message over SSL. Returns 0 on success, -1 on error. */
int protocol_send(SSL *ssl, uint8_t type, const void *payload, uint16_t len);

/* Receive a framed message over SSL.
 * Caller must free(*payload_out) after use.
 * Returns 0 on success, -1 on error/disconnect. */
int protocol_recv(SSL *ssl, uint8_t *type_out, uint8_t **payload_out,
                  uint16_t *len_out);

#endif /* PROTOCOL_H */
