#ifndef LOGMACRO_H
#define LOGMACRO_H

#include "colorcodes.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* (#6) online/offline yerine büyük harfli enum değerleri */
typedef enum { LOG_STATUS_ONLINE = 1, LOG_STATUS_OFFLINE = 0 } LogStatus;

/* Eski uyumluluk makroları — kademeli geçiş için */
#define online LOG_STATUS_ONLINE
#define offline LOG_STATUS_OFFLINE

/* Log bağlamlarını temsil eden enum */
typedef enum { server, client, auth, database, rsa, unknown } LogContext;

/* Bağlamı string'e dönüştüren yardımcı makro */
#define CONTEXT_TO_STRING(context)                                             \
  (context == server     ? "SERVER"                                            \
   : context == client   ? "CLIENT"                                            \
   : context == auth     ? "AUTH"                                              \
   : context == database ? "DATABASE"                                          \
   : context == rsa      ? "RSA"                                               \
                         : "UNKNOWN")

/* (#7) Thread-safe timestamp — caller-provided buffer */
static inline const char *get_timestamp_safe(char *buf, size_t buf_size) {
  time_t now = time(NULL);
  struct tm t;
  localtime_r(&now, &t);
  strftime(buf, buf_size, "%Y-%m-%d %H:%M:%S", &t);
  return buf;
}

/* (#7) Eski API — makrolar artık get_timestamp_r kullanıyor ama uyumluluk için
 */
static inline char *get_timestamp() {
  static char buffer[32];
  get_timestamp_safe(buffer, sizeof(buffer));
  return buffer;
}

/* (#8) Log dosyasını aç (her çağrıda fopen/fclose — bilinen performans sorunu)
 */
static inline FILE *get_log_file() { return fopen("client_log.log", "a"); }

/* Log loop info makrosu */
#define LOG_LOOPINFO(context, fmt, ...)                                        \
  fprintf(stdout, RESET BWHT "[LOG][%s][INFO] " YEL fmt RESET "\n",            \
          CONTEXT_TO_STRING(context), ##__VA_ARGS__)

/* (#10) LOG_MSG artık do/while ile sarılı — dangling else riski giderildi */
#define LOG_MSG(client_name, status)                                           \
  do {                                                                         \
    fprintf(stdout, RESET BWHT "[%s][%s]: ",                                   \
            (status == LOG_STATUS_ONLINE ? "ONLINE" : "OFFLINE"),              \
            client_name);                                                      \
    fflush(stdout);                                                            \
  } while (0)

/* Log başarı makrosu */
#define LOG_SUCCESS(context, fmt, ...)                                         \
  do {                                                                         \
    if (context != server) {                                                   \
      FILE *log_file = get_log_file();                                         \
      if (log_file) {                                                          \
        fprintf(log_file, "[%s] [LOG][%s][SUCCESS] " fmt "\n",                 \
                get_timestamp(), CONTEXT_TO_STRING(context), ##__VA_ARGS__);   \
        fclose(log_file);                                                      \
      } else {                                                                 \
        fprintf(stderr,                                                        \
                RESET BRED "[%s] [LOG][%s][ERROR] Failed to open log file\n",  \
                get_timestamp(), CONTEXT_TO_STRING(context));                  \
      }                                                                        \
    } else {                                                                   \
      fprintf(stdout,                                                          \
              RESET BWHT "[%s] [LOG][%s][SUCCESS] " BGRN fmt RESET "\n",       \
              get_timestamp(), CONTEXT_TO_STRING(context), ##__VA_ARGS__);     \
    }                                                                          \
  } while (0)

/* Log bilgi makrosu */
#define LOG_INFO(context, fmt, ...)                                            \
  do {                                                                         \
    if (context != server) {                                                   \
      FILE *log_file = get_log_file();                                         \
      if (log_file) {                                                          \
        fprintf(log_file, "[%s] [LOG][%s][INFO] " fmt "\n", get_timestamp(),   \
                CONTEXT_TO_STRING(context), ##__VA_ARGS__);                    \
        fclose(log_file);                                                      \
      } else {                                                                 \
        fprintf(stderr,                                                        \
                RESET BRED "[%s] [LOG][%s][ERROR] Failed to open log file\n",  \
                get_timestamp(), CONTEXT_TO_STRING(context));                  \
      }                                                                        \
    } else {                                                                   \
      fprintf(stdout, RESET BWHT "[%s] [LOG][%s][INFO] " fmt "\n",             \
              get_timestamp(), CONTEXT_TO_STRING(context), ##__VA_ARGS__);     \
    }                                                                          \
  } while (0)

/* (#11) Log hata makrosu — errno kontrolü kaldırıldı (güvenilir değil) */
#define LOG_ERROR(context, fmt, ...)                                           \
  do {                                                                         \
    if (context != server) {                                                   \
      FILE *log_file = get_log_file();                                         \
      if (log_file) {                                                          \
        fprintf(log_file, "[%s] [LOG][%s][ERROR] " fmt "\n", get_timestamp(),  \
                CONTEXT_TO_STRING(context), ##__VA_ARGS__);                    \
        fclose(log_file);                                                      \
      } else {                                                                 \
        fprintf(stderr,                                                        \
                RESET BRED "[%s] [LOG][%s][ERROR] Failed to open log file\n",  \
                get_timestamp(), CONTEXT_TO_STRING(context));                  \
      }                                                                        \
    } else {                                                                   \
      fprintf(stderr, RESET BWHT "[%s] [LOG][%s][ERROR] " BRED fmt "\n" RESET, \
              get_timestamp(), CONTEXT_TO_STRING(context), ##__VA_ARGS__);     \
    }                                                                          \
  } while (0)

#endif /* LOGMACRO_H */
