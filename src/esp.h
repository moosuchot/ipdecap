/*
  Copyright (c) 2012-2016 Loïc Pefferkorn <loic-ipdecap@loicp.eu>
  ipdecap [http://loicpefferkorn.net/ipdecap]

  This file is part of ipdecap.

  Ipdecap is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  Ipdecap is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with ipdecap.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include "utils.h"

void print_algorithms(void);
void process_esp_packet(const u_char *payload, const int payload_len, pcap_hdr *new_packet_hdr, u_char *new_packet_payload);
void dump_flows(void);
int add_flow(char *ip_src, char *ip_dst, char *crypt_name, char *auth_name, char *key, char *spi);
void flows_cleanup(void);
struct llflow_t * find_flow(char *ip_src, char *ip_dst, u_int32_t spi);
int parse_esp_conf(char *filename);
struct crypt_method_t * find_crypt_method(char *crypt_name);
struct auth_method_t * find_auth_method(char *auth_name);

#define ESP_SPI_LEN       8

typedef struct sockaddr_storage sa_sto;

typedef union address {
  struct sockaddr sa;
  struct sockaddr_in sa_in;
  struct sockaddr_in6 sa_in6;
  struct sockaddr_storage sa_sto;
} address_t;

typedef struct esp_packet_t {
  u_int32_t spi;
  u_int32_t seq;
  u_char iv[EVP_MAX_IV_LENGTH];
  u_int8_t pad_len;
  u_int8_t next_header;
} __attribute__ ((__packed__)) esp_packet_t;

// ESP encryption methods
typedef struct crypt_method_t {
  char *name;             // Name used in ESP configuration file
  char *openssl_cipher;   // OpenSSL internal name
  struct crypt_method_t *next;
} crypt_method_t;

// ESP authentication methods
typedef struct auth_method_t {
  char *name;             // Name used in ESP configuration file
  char *openssl_auth;     // OpenSSL internal name,  not yet used (no verification made)
  int len;                // Digest bytes length
  struct auth_method_t *next;
} auth_method_t;

// Roughly a line of the ESP configuration file, plus internals pointers
typedef struct llflow_t {
  address_t addr_src;
  address_t addr_dst;
  EVP_CIPHER_CTX ctx;
  unsigned char *key;
  u_int32_t spi;
  char *crypt_name;
  char *auth_name;
  crypt_method_t *crypt_method;
  auth_method_t *auth_method;
  struct llflow_t *next;
} llflow_t;

