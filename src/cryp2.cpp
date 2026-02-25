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
#include <cstring>
#include <iostream>

#include "colorcodes.h"
#include "cryp2.h"
#include "logmacro.h"

// RSA açık anahtarı yükler
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

// RSA özel anahtarı yükler
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

// Hata mesajlarını yazdırır
void handle_openssl_error() {
  ERR_print_errors_fp(stderr);
  exit(EXIT_FAILURE);
}

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
  int result =
      RSA_public_encrypt(strlen(plaintext) + 1, // Null karakteri de dahil et
                         (unsigned char *)plaintext, (unsigned char *)encrypted,
                         public_key, PADDING);
  RSA_free(public_key);
  if (result == -1) {
    // K9 fix: handle_openssl_error() exit eder, sonraki kod unreachable idi —
    // kaldırıldı
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
  decrypted[result] = '\0'; // Null sonlandırma
  return decrypted;
}