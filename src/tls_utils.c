#include "tls_utils.h"
#include "logmacro.h"
#include <openssl/err.h>

SSL_CTX *create_server_tls_context(const char *cert_path,
                                   const char *key_path) {
  SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
  if (!ctx) {
    LOG_ERROR(server, "Failed to create SSL context");
    ERR_print_errors_fp(stderr);
    return NULL;
  }

  /* Enforce TLS 1.3 minimum */
  SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);

  if (SSL_CTX_use_certificate_file(ctx, cert_path, SSL_FILETYPE_PEM) <= 0) {
    LOG_ERROR(server, "Failed to load certificate: %s", cert_path);
    ERR_print_errors_fp(stderr);
    SSL_CTX_free(ctx);
    return NULL;
  }

  if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0) {
    LOG_ERROR(server, "Failed to load private key: %s", key_path);
    ERR_print_errors_fp(stderr);
    SSL_CTX_free(ctx);
    return NULL;
  }

  if (!SSL_CTX_check_private_key(ctx)) {
    LOG_ERROR(server, "Private key does not match certificate");
    SSL_CTX_free(ctx);
    return NULL;
  }

  LOG_SUCCESS(server, "TLS 1.3 server context created.");
  return ctx;
}

SSL_CTX *create_client_tls_context(void) {
  SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
  if (!ctx) {
    LOG_ERROR(client, "Failed to create SSL context");
    ERR_print_errors_fp(stderr);
    return NULL;
  }

  SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);

  /* Self-signed cert for dev — skip verification */
  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

  LOG_SUCCESS(client, "TLS 1.3 client context created.");
  return ctx;
}

SSL *tls_server_accept(SSL_CTX *ctx, int client_fd) {
  SSL *ssl = SSL_new(ctx);
  if (!ssl) {
    LOG_ERROR(server, "Failed to create SSL object");
    return NULL;
  }

  SSL_set_fd(ssl, client_fd);

  if (SSL_accept(ssl) <= 0) {
    LOG_ERROR(server, "TLS handshake failed");
    ERR_print_errors_fp(stderr);
    SSL_free(ssl);
    return NULL;
  }

  LOG_SUCCESS(server, "TLS handshake completed (version: %s)",
              SSL_get_version(ssl));
  return ssl;
}

SSL *tls_client_connect(SSL_CTX *ctx, int socket_fd) {
  SSL *ssl = SSL_new(ctx);
  if (!ssl) {
    LOG_ERROR(client, "Failed to create SSL object");
    return NULL;
  }

  SSL_set_fd(ssl, socket_fd);

  if (SSL_connect(ssl) <= 0) {
    LOG_ERROR(client, "TLS handshake failed");
    ERR_print_errors_fp(stderr);
    SSL_free(ssl);
    return NULL;
  }

  LOG_SUCCESS(client, "TLS handshake completed (version: %s)",
              SSL_get_version(ssl));
  return ssl;
}

void tls_cleanup(SSL *ssl) {
  if (ssl) {
    SSL_shutdown(ssl);
    SSL_free(ssl);
  }
}
