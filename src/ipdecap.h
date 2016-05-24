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

#include "utils.h"

void print_version(void);
void verbose(const char *format, ...);
void copy_n_shift(u_char *ptr, u_char *dst, u_int len);
void usage(void);
void handle_packets(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);

void remove_ieee8021q_header(const u_char *in_payload, const int in_payload_len, pcap_hdr *out_pkthdr, u_char *out_payload);
void process_nonip_packet(const u_char *payload, const int payload_len, pcap_hdr *new_packet_hdr, u_char *new_packet_payload);

void parse_options(int argc, char **argv);
