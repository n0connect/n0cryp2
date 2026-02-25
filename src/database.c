/**
 * @file database.c
 * @author Ahmet Berat (niceshotfree@gmail.com)
 * @brief
 * @version 0.1
 * @date 2024-11-25
 *
 * @copyright Copyright (c) 2024
 *
 */
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "database.h"

/* (#29) Şifreler hâlâ plaintext — ileri aşamada hash'lenecek */
static const char *usernames[] = {"n0n0", "z0z0", "root", "admin"};
static const char *passwords[] = {"n0n0", "z0z0", "root", "admin"};
/* (#30) user_count otomatik hesaplanıyor */
static const int user_count = (int)(sizeof(usernames) / sizeof(usernames[0]));

/* Kullanıcı adı ve şifre doğrulama fonksiyonu */
bool check_credentials(const char *username, const char *password) {
  for (int i = 0; i < user_count; i++) {
    /* (#31) Trigraph sorunu düzeltildi: (??) yerine (==) */
    /* (#33) Credential log'lama kaldırıldı — güvenlik riski */
    LOG_LOOPINFO(database, "Checking user index [%d]", i);
    /* (#32) strcmp timing attack riski biliniyor — ileri aşamada constant-time
     * compare */
    if (strcmp(usernames[i], username) == 0 &&
        strcmp(passwords[i], password) == 0) {
      return true;
    }
  }
  return false;
}
