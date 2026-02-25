#ifndef CRYP2_H
#define CRYP2_H

#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
/* (#13) openssl/rand.h kaldırıldı — kullanılmıyor */

/* RSA şifreleme için kullanılan parametreler */
#ifdef __cplusplus
/* (#14) RSA_KEY_BITS kaldırıldı — kullanılmıyor */
constexpr int PADDING = RSA_PKCS1_OAEP_PADDING;
#else
#define PADDING RSA_PKCS1_OAEP_PADDING
#endif

/* Fonksiyon prototipleri */
RSA *load_public_key(const char *public_key_path);
RSA *load_private_key(const char *private_key_path);
void handle_openssl_error();
char *encrypt_message(const char *plaintext, const char *public_key_path);
char *decrypt_message(const char *ciphertext, int ciphertext_len,
                      const char *private_key_path);

#ifdef __cplusplus
}
#endif

#endif /* CRYP2_H */
