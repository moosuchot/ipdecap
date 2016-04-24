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
#include "gre.h"

/*
 * Decapsulate a GRE packet
 *
 */
void process_gre_packet(const u_char *payload, const int payload_len, pcap_hdr *new_packet_hdr, u_char *new_packet_payload) {

  //TODO: check si version == 0 1 non supporté car pptp)
  int packet_size = 0;
  u_int16_t flags;
  const u_char *payload_src = NULL;
  u_char *payload_dst = NULL;
  const struct ip *ip_hdr = NULL;
  const struct grehdr *gre_hdr = NULL;

  payload_src = payload;
  payload_dst = new_packet_payload;

  // Copy ethernet header
  memcpy(payload_dst, payload_src, sizeof(struct ether_header));
  payload_src += sizeof(struct ether_header);
  payload_dst += sizeof(struct ether_header);
  packet_size = sizeof(struct ether_header);

  // Read encapsulating IP header to find offset to GRE header
  ip_hdr = (const struct ip *) payload_src;
  payload_src += (ip_hdr->ip_hl *4);

  debug_print("\tGRE: outer IP - hlen:%i iplen:%02i protocol:%02x\n",
    (ip_hdr->ip_hl *4), ntohs(ip_hdr->ip_len), ip_hdr->ip_p);

  packet_size += ntohs(ip_hdr->ip_len) - ip_hdr->ip_hl*4;

  // Read GRE header to find offset to encapsulated IP packet
  gre_hdr = (const struct grehdr *) payload_src;
  debug_print("\tGRE - GRE header: flags:%u protocol:%u\n", gre_hdr->flags, gre_hdr->next_protocol);

  packet_size -= sizeof(struct grehdr);
  payload_src += sizeof(struct grehdr);
  flags = ntohs(gre_hdr->flags);

  if (flags & GRE_CHECKSUM || flags & GRE_ROUTING) {
    payload_src += 4; // Both checksum and offset fields are present
    packet_size -= 4;
  }

  if (flags & GRE_KEY) {
    payload_src += 4;
    packet_size -= 4;
  }

  if (flags & GRE_SEQ) {
    payload_src += 4;
    packet_size -= 4;
  }

  memcpy(payload_dst, payload_src, packet_size);
  new_packet_hdr->len = packet_size;

}
