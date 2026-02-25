#ifndef DATABASE_H
#define DATABASE_H

#include "logmacro.h"
#include <stdbool.h>

/* Kullanıcı adı ve şifre doğrulama fonksiyonu */
bool check_credentials(const char *username, const char *password);

/* (#15) Dead code yorum satırı kaldırıldı */

#endif /* DATABASE_H */