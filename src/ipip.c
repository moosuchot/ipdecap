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

/* Decapsulate an IPIP packet
 *
*/
#include <netinet/ip.h>
#include <pcap/pcap.h>
#include <pcap/vlan.h>
#include <net/ethernet.h>
#include <string.h>
#include "ipdecap.h"
#include "utils.h"

void process_ipip_packet(const u_char *payload, const int payload_len, pcap_hdr *new_packet_hdr, u_char *new_packet_payload) {

  int packet_size = 0;
  const u_char *payload_src = NULL;
  u_char *payload_dst = NULL;
  const struct ip *ip_hdr = NULL;

  payload_src = payload;
  payload_dst = new_packet_payload;

  // Copy ethernet header
  memcpy(payload_dst, payload_src, sizeof(struct ether_header));
  payload_src += sizeof(struct ether_header);
  payload_dst += sizeof(struct ether_header);
  packet_size = sizeof(struct ether_header);

  // Read encapsulating IP header to find offset to encapsulted IP packet
  ip_hdr = (const struct ip *) payload_src;

  debug_print("\tIPIP: outer IP - hlen:%i iplen:%02i protocol:%02x\n",
      (ip_hdr->ip_hl *4), ntohs(ip_hdr->ip_len), ip_hdr->ip_p);

  // Shift to encapsulated IP header, read total length
  payload_src += ip_hdr->ip_hl *4;
  ip_hdr = (const struct ip *) payload_src;

  debug_print("\tIPIP: inner IP - hlen:%i iplen:%02i protocol:%02x\n",
      (ip_hdr->ip_hl *4), ntohs(ip_hdr->ip_len), ip_hdr->ip_p);

  memcpy(payload_dst, payload_src, ntohs(ip_hdr->ip_len));
  packet_size += ntohs(ip_hdr->ip_len);

  new_packet_hdr->len = packet_size;
}
