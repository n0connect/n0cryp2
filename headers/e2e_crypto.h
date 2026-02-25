#ifndef E2E_CRYPTO_H
#define E2E_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define E2E_KEY_LEN 32   /* X25519 key size */
#define E2E_NONCE_LEN 12 /* AES-GCM nonce */
#define E2E_TAG_LEN 16   /* AES-GCM auth tag */

typedef struct {
  uint8_t public_key[E2E_KEY_LEN];
  uint8_t private_key[E2E_KEY_LEN];
} E2EKeyPair;

/* Generate X25519 keypair. Returns 0 on success, -1 on error. */
int e2e_generate_keypair(E2EKeyPair *kp);

/* Compute shared secret and derive AES-256 key via HKDF.
 * my_private: 32-byte X25519 private key
 * their_public: 32-byte X25519 public key
 * derived_key_out: 32-byte AES-256 key output
 * Returns 0 on success, -1 on error. */
int e2e_derive_key(const uint8_t *my_private, const uint8_t *their_public,
                   uint8_t *derived_key_out);

/* AES-256-GCM encrypt.
 * key: 32-byte AES key
 * plaintext/pt_len: data to encrypt
 * nonce_out: 12-byte random nonce (generated internally)
 * ct_out: ciphertext + 16-byte tag appended (must be at least pt_len + 16)
 * ct_len_out: total output length (pt_len + 16)
 * Returns 0 on success, -1 on error. */
int e2e_encrypt(const uint8_t *key, const uint8_t *plaintext, int pt_len,
                uint8_t *nonce_out, uint8_t *ct_out, int *ct_len_out);

/* AES-256-GCM decrypt.
 * key: 32-byte AES key
 * nonce: 12-byte nonce
 * ciphertext: ciphertext + 16-byte tag appended
 * ct_len: total ciphertext length (message + 16 tag)
 * pt_out: plaintext output (must be at least ct_len - 16)
 * pt_len_out: plaintext length
 * Returns 0 on success, -1 on error (auth failed). */
int e2e_decrypt(const uint8_t *key, const uint8_t *nonce,
                const uint8_t *ciphertext, int ct_len, uint8_t *pt_out,
                int *pt_len_out);

#endif /* E2E_CRYPTO_H */
