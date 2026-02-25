#ifndef TLS_UTILS_H
#define TLS_UTILS_H

#include <openssl/ssl.h>

/* Create TLS 1.3 server context with certificate and private key */
SSL_CTX *create_server_tls_context(const char *cert_path, const char *key_path);

/* Create TLS 1.3 client context (no client certificate) */
SSL_CTX *create_client_tls_context(void);

/* Perform TLS accept on an already-accepted socket fd. Returns SSL* or NULL. */
SSL *tls_server_accept(SSL_CTX *ctx, int client_fd);

/* Perform TLS connect on a connected socket fd. Returns SSL* or NULL. */
SSL *tls_client_connect(SSL_CTX *ctx, int socket_fd);

/* Shutdown and free SSL object */
void tls_cleanup(SSL *ssl);

#endif /* TLS_UTILS_H */
