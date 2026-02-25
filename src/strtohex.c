/* (#34) ctype.h kaldırıldı — kullanılmıyordu */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "strtohex.h"

/**
 * Converts a character to its hexadecimal representation.
 */
static char char_to_hex_digit(unsigned char value) {
  return (value < 10) ? ('0' + value) : ('A' + (value - 10));
}

/**
 * Converts a single hexadecimal digit to its numeric value.
 * (#35) Returns -1 for invalid input instead of silent 0.
 */
static int hex_digit_to_value(char hex) {
  if (hex >= '0' && hex <= '9')
    return hex - '0';
  if (hex >= 'A' && hex <= 'F')
    return hex - 'A' + 10;
  if (hex >= 'a' && hex <= 'f')
    return hex - 'a' + 10;
  return -1;
}

char *str_to_hex(const char *str, size_t size) {
  if (!str || size == 0)
    return NULL;

  char *hex_str = (char *)malloc(size * 2 + 1);
  if (!hex_str)
    return NULL;

  for (size_t i = 0; i < size; ++i) {
    unsigned char byte = (unsigned char)str[i];
    hex_str[i * 2] = char_to_hex_digit(byte >> 4);
    hex_str[i * 2 + 1] = char_to_hex_digit(byte & 0x0F);
  }

  hex_str[size * 2] = '\0';
  return hex_str;
}

char *hex_to_str(const char *hex_str, size_t size) {
  if (!hex_str || size == 0 || size % 2 != 0)
    return NULL;

  size_t str_size = size / 2;
  char *str = (char *)malloc(str_size + 1);
  if (!str)
    return NULL;

  for (size_t i = 0; i < str_size; ++i) {
    int high_nibble = hex_digit_to_value(hex_str[i * 2]);
    int low_nibble = hex_digit_to_value(hex_str[i * 2 + 1]);
    /* (#35) Geçersiz hex input'ta NULL döner */
    if (high_nibble < 0 || low_nibble < 0) {
      free(str);
      return NULL;
    }
    str[i] = (char)((high_nibble << 4) | low_nibble);
  }

  str[str_size] = '\0';
  return str;
}
