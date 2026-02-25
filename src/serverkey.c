#include <limits.h> // PATH_MAX için
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // getcwd için

#include "serverkey.h"

// Çalışma dizinine göre dinamik olarak dosya yolunu oluştur
const char *getPublicKeyPath() {
  static char path[PATH_MAX];
  char cwd[PATH_MAX];
  if (getcwd(cwd, sizeof(cwd)) == NULL) {
    perror("getcwd() error");
    exit(EXIT_FAILURE);
  }
  snprintf(path, sizeof(path), "%s/server-key/public_key.pem", cwd);
  return path;
}

const char *getPrivateKeyPath() {
  static char path[PATH_MAX];
  char cwd[PATH_MAX];
  if (getcwd(cwd, sizeof(cwd)) == NULL) {
    perror("getcwd() error");
    exit(EXIT_FAILURE);
  }
  snprintf(path, sizeof(path), "%s/server-key/private_key.pem", cwd);
  return path;
}