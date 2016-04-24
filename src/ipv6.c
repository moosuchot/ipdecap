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

#include <netinet/ip.h>
#include <pcap/pcap.h>
#include <pcap/vlan.h>
#include <net/ethernet.h>
#include <string.h>
#include "ipdecap.h"
#include "utils.h"
#include "ipv6.h"

/* Decapsulate an IPv6 packet
 *
 */
void process_ipv6_packet(const u_char *payload, const int payload_len, pcap_hdr *new_packet_hdr, u_char *new_packet_payload) {

  int packet_size = 0;
  const u_char *payload_src = NULL;
  u_char *payload_dst = NULL;
  const struct ip *ip_hdr = NULL;
  uint16_t ethertype;

  payload_src = payload;
  payload_dst = new_packet_payload;

  // Copy src and dst ether addr
  memcpy(payload_dst, payload_src, 2*sizeof(struct ether_addr));
  payload_src += 2*sizeof(struct ether_addr);
  payload_dst += 2*sizeof(struct ether_addr);

  // Set ethernet type to IPv6
  ethertype = htons(ETHERTYPE_IPV6);
  memcpy(payload_dst, &ethertype, member_size(struct ether_header, ether_type));
  payload_src += member_size(struct ether_header, ether_type);
  payload_dst += member_size(struct ether_header, ether_type);

  // Read encapsulating IPv4 header to find header lenght and offset to encapsulated IPv6 packet
  ip_hdr = (const struct ip *) payload_src;

  packet_size = payload_len - (ip_hdr->ip_hl *4);

  debug_print("\tIPv6: outer IP - hlen:%i iplen:%02i protocol:%02x\n",
      (ip_hdr->ip_hl *4), ntohs(ip_hdr->ip_len), ip_hdr->ip_p);

  // Shift to encapsulated IPv6 packet, then copy
  payload_src += ip_hdr->ip_hl *4;

  memcpy(payload_dst, payload_src, packet_size);
  new_packet_hdr->len = packet_size;
}
