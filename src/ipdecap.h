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

/* I used previously OpenSSL EVP_MAX_KEY_LENGTH,
 * but it has changed between OpenSSL 1.0.1 and 1.1.0 versions.
 */

#pragma once

typedef struct pcap_pkthdr pcap_hdr;

typedef struct sockaddr_storage sa_sto;

typedef union address {
  struct sockaddr sa;
  struct sockaddr_in sa_in;
  struct sockaddr_in6 sa_in6;
  struct sockaddr_storage sa_sto;
} address_t;

void print_version(void);
void print_algorithms(void);
void verbose(const char *format, ...);
void copy_n_shift(u_char *ptr, u_char *dst, u_int len);
int add_flow(char *ip_src, char *ip_dst, char *crypt_name, char *auth_name, char *key, char *spi);
void dump_flows(void);
void usage(void);
void flows_cleanup(void);
struct llflow_t * find_flow(char *ip_src, char *ip_dst, u_int32_t spi);
int parse_esp_conf(char *filename);
struct crypt_method_t * find_crypt_method(char *crypt_name);
struct auth_method_t * find_auth_method(char *auth_name);
void handle_packets(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);

void remove_ieee8021q_header(const u_char *in_payload, const int in_payload_len, pcap_hdr *out_pkthdr, u_char *out_payload);
void process_nonip_packet(const u_char *payload, const int payload_len, pcap_hdr *new_packet_hdr, u_char *new_packet_payload);
void process_ipip_packet(const u_char *payload, const int payload_len, pcap_hdr *new_packet_hdr, u_char *new_packet_payload);
void process_ipv6_packet(const u_char *payload, const int payload_len, pcap_hdr *new_packet_hdr, u_char *new_packet_payload);
void process_gre_packet(const u_char *payload, const int payload_len, pcap_hdr *new_packet_hdr, u_char *new_packet_payload);
void process_esp_packet(const u_char *payload, const int payload_len, pcap_hdr *new_packet_hdr, u_char *new_packet_payload);

struct llflow_t *flow_head = NULL;
void parse_options(int argc, char **argv);
