/**
 * @file cryp2.cpp
 * @author Ahmet Berat (niceshotfree@gmail.com)
 * @brief
 * @version 0.1
 * @date 2024-11-19
 *
 * @copyright Copyright (c) 2024
 *
 */
/* (#38) iostream kaldırıldı — kullanılmıyordu */
#include <cstring>

#include "colorcodes.h"
#include "cryp2.h"
#include "logmacro.h"

/* RSA açık anahtarı yükler */
RSA *load_public_key(const char *public_key_path) {
  FILE *pub_file = fopen(public_key_path, "r");
  if (!pub_file) {
    LOG_ERROR(rsa, "Failed to open the public key file");
    exit(EXIT_FAILURE);
  }
  RSA *public_key = PEM_read_RSA_PUBKEY(pub_file, nullptr, nullptr, nullptr);
  fclose(pub_file);
  if (!public_key)
    handle_openssl_error();
  return public_key;
}

/* RSA özel anahtarı yükler */
RSA *load_private_key(const char *private_key_path) {
  FILE *priv_file = fopen(private_key_path, "r");
  if (!priv_file) {
    LOG_ERROR(rsa, "Failed to open the private key file");
    exit(EXIT_FAILURE);
  }
  RSA *private_key =
      PEM_read_RSAPrivateKey(priv_file, nullptr, nullptr, nullptr);
  fclose(priv_file);
  if (!private_key)
    handle_openssl_error();
  return private_key;
}

/* Hata mesajlarını yazdırır */
void handle_openssl_error() {
  ERR_print_errors_fp(stderr);
  exit(EXIT_FAILURE);
}

/*
 * (#40) NOT: OAEP padding ile 2048-bit RSA max 245 byte plaintext destekler.
 *       BUFFER_SIZE(256) > 245 olduğundan uzun mesajlarda fail olur.
 *       İleride hybrid RSA+AES yaklaşımına geçilmeli (#41).
 *
 * (#39) NOT: Her çağrıda dosyadan key yükleniyor — ileride cache'lenmeli.
 */
char *encrypt_message(const char *plaintext, const char *public_key_path) {
  RSA *public_key = load_public_key(public_key_path);
  int rsa_size = RSA_size(public_key);
  char *encrypted = (char *)calloc(rsa_size, sizeof(char));
  LOG_SUCCESS(rsa, "RSA SIZE: %d", rsa_size);

  if (!encrypted) {
    LOG_ERROR(rsa, "Failed to allocate memory for encryption");
    RSA_free(public_key);
    exit(EXIT_FAILURE);
  }

  int plaintext_len = (int)strlen(plaintext) + 1; /* null dahil */
  int max_payload = rsa_size - 42;                /* OAEP overhead for SHA-1 */
  if (plaintext_len > max_payload) {
    LOG_ERROR(rsa, "Plaintext too long for RSA (%d > %d)", plaintext_len,
              max_payload);
    RSA_free(public_key);
    free(encrypted);
    exit(EXIT_FAILURE);
  }

  int result =
      RSA_public_encrypt(plaintext_len, (unsigned char *)plaintext,
                         (unsigned char *)encrypted, public_key, PADDING);
  RSA_free(public_key);
  if (result == -1) {
    free(encrypted);
    handle_openssl_error();
  }

  return encrypted;
}

char *decrypt_message(const char *encrypted_message, int encrypted_length,
                      const char *private_key_path) {
  LOG_SUCCESS(rsa, "Start Decryption function.");
  RSA *private_key = load_private_key(private_key_path);
  LOG_SUCCESS(rsa, "Loaded Private key.");
  int rsa_size = RSA_size(private_key);
  LOG_SUCCESS(rsa, "Calculated RSA SIZE(%d).", rsa_size);
  char *decrypted = (char *)malloc(rsa_size);
  LOG_SUCCESS(rsa, "Allocated memory.");
  if (!decrypted) {
    LOG_ERROR(rsa, "Failed to allocate memory for decryption");
    RSA_free(private_key);
    exit(EXIT_FAILURE);
  }
  LOG_SUCCESS(rsa, "Private key DECRYPT.");
  int result =
      RSA_private_decrypt(encrypted_length, (unsigned char *)encrypted_message,
                          (unsigned char *)decrypted, private_key, PADDING);
  RSA_free(private_key);
  if (result == -1) {
    free(decrypted);
    handle_openssl_error();
  }
  decrypted[result] = '\0';
  return decrypted;
}