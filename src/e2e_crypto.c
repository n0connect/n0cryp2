#include "e2e_crypto.h"
#include "logmacro.h"

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <string.h>

int e2e_generate_keypair(E2EKeyPair *kp) {
  EVP_PKEY *pkey = NULL;
  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
  if (!pctx)
    goto err;
  if (EVP_PKEY_keygen_init(pctx) <= 0)
    goto err;
  if (EVP_PKEY_keygen(pctx, &pkey) <= 0)
    goto err;

  size_t key_len = E2E_KEY_LEN;
  if (EVP_PKEY_get_raw_public_key(pkey, kp->public_key, &key_len) <= 0)
    goto err;
  key_len = E2E_KEY_LEN;
  if (EVP_PKEY_get_raw_private_key(pkey, kp->private_key, &key_len) <= 0)
    goto err;

  EVP_PKEY_free(pkey);
  EVP_PKEY_CTX_free(pctx);
  LOG_SUCCESS(rsa, "X25519 keypair generated.");
  return 0;

err:
  ERR_print_errors_fp(stderr);
  if (pkey)
    EVP_PKEY_free(pkey);
  if (pctx)
    EVP_PKEY_CTX_free(pctx);
  return -1;
}

int e2e_derive_key(const uint8_t *my_private, const uint8_t *their_public,
                   uint8_t *derived_key_out) {
  int ret = -1;
  uint8_t shared_secret[E2E_KEY_LEN];

  /* X25519 DH */
  EVP_PKEY *my_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL,
                                                  my_private, E2E_KEY_LEN);
  EVP_PKEY *peer_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL,
                                                   their_public, E2E_KEY_LEN);
  if (!my_key || !peer_key)
    goto cleanup;

  EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new(my_key, NULL);
  if (!dctx)
    goto cleanup;
  if (EVP_PKEY_derive_init(dctx) <= 0)
    goto cleanup_ctx;
  if (EVP_PKEY_derive_set_peer(dctx, peer_key) <= 0)
    goto cleanup_ctx;

  size_t secret_len = E2E_KEY_LEN;
  if (EVP_PKEY_derive(dctx, shared_secret, &secret_len) <= 0)
    goto cleanup_ctx;

  /* HKDF-SHA256 to derive AES key */
  EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
  if (!kdf)
    goto cleanup_ctx;

  EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
  EVP_KDF_free(kdf);
  if (!kctx)
    goto cleanup_ctx;

  const char *digest_name = "SHA256";
  const char *info_str = "n0cryp2-e2e-v1";
  uint8_t salt[1] = {0}; /* minimal salt */
  OSSL_PARAM params[5];
  params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                               (char *)digest_name, 0);
  params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                                shared_secret, secret_len);
  params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt,
                                                sizeof(salt));
  params[3] = OSSL_PARAM_construct_octet_string(
      OSSL_KDF_PARAM_INFO, (char *)info_str, strlen(info_str));
  params[4] = OSSL_PARAM_construct_end();

  if (EVP_KDF_derive(kctx, derived_key_out, E2E_KEY_LEN, params) <= 0) {
    EVP_KDF_CTX_free(kctx);
    goto cleanup_ctx;
  }
  EVP_KDF_CTX_free(kctx);

  ret = 0;
  LOG_SUCCESS(rsa, "E2E key derived via X25519 + HKDF-SHA256.");

cleanup_ctx:
  EVP_PKEY_CTX_free(dctx);
cleanup:
  OPENSSL_cleanse(shared_secret, sizeof(shared_secret));
  if (my_key)
    EVP_PKEY_free(my_key);
  if (peer_key)
    EVP_PKEY_free(peer_key);
  if (ret != 0)
    ERR_print_errors_fp(stderr);
  return ret;
}

int e2e_encrypt(const uint8_t *key, const uint8_t *plaintext, int pt_len,
                uint8_t *nonce_out, uint8_t *ct_out, int *ct_len_out) {
  /* Generate random nonce */
  if (RAND_bytes(nonce_out, E2E_NONCE_LEN) <= 0)
    return -1;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
    return -1;

  int ret = -1;
  if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) <= 0)
    goto done;
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, E2E_NONCE_LEN, NULL) <=
      0)
    goto done;
  if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce_out) <= 0)
    goto done;

  int outl = 0;
  if (EVP_EncryptUpdate(ctx, ct_out, &outl, plaintext, pt_len) <= 0)
    goto done;
  int total = outl;

  if (EVP_EncryptFinal_ex(ctx, ct_out + total, &outl) <= 0)
    goto done;
  total += outl;

  /* Append 16-byte auth tag */
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, E2E_TAG_LEN,
                          ct_out + total) <= 0)
    goto done;
  total += E2E_TAG_LEN;

  *ct_len_out = total;
  ret = 0;

done:
  EVP_CIPHER_CTX_free(ctx);
  return ret;
}

int e2e_decrypt(const uint8_t *key, const uint8_t *nonce,
                const uint8_t *ciphertext, int ct_len, uint8_t *pt_out,
                int *pt_len_out) {
  if (ct_len < E2E_TAG_LEN)
    return -1;

  int data_len = ct_len - E2E_TAG_LEN;
  const uint8_t *tag = ciphertext + data_len;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
    return -1;

  int ret = -1;
  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) <= 0)
    goto done;
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, E2E_NONCE_LEN, NULL) <=
      0)
    goto done;
  if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) <= 0)
    goto done;

  int outl = 0;
  if (EVP_DecryptUpdate(ctx, pt_out, &outl, ciphertext, data_len) <= 0)
    goto done;
  int total = outl;

  /* Set expected tag */
  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, E2E_TAG_LEN,
                          (void *)tag) <= 0)
    goto done;

  /* Verify tag and finalize */
  if (EVP_DecryptFinal_ex(ctx, pt_out + total, &outl) <= 0) {
    LOG_ERROR(rsa, "E2E decrypt: authentication tag verification FAILED");
    goto done;
  }
  total += outl;
  *pt_len_out = total;
  ret = 0;

done:
  EVP_CIPHER_CTX_free(ctx);
  return ret;
}
