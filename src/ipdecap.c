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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap/pcap.h>
#include <pcap/vlan.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <openssl/evp.h>
#include <errno.h>
#include <limits.h>
#include <getopt.h>
#include <stdbool.h>
#include <inttypes.h>
#include <err.h>

#include "config.h"
#include "ipdecap.h"
#include "utils.h"
#include "gre.h"
#include "esp.h"
#include "ipip.h"
#include "ipv6.h"

// Command line parameters
static const char *args_str = "vi:o:c:f:Vl";


static const struct option args_long[] = {
  { "input",      required_argument,  NULL, 'i'},
  { "output",     required_argument,  NULL, 'o'},
  { "esp_config", required_argument,  NULL, 'c'},
  { "filter",     required_argument,  NULL, 'f'},
  { "list",       no_argument,        NULL, 'l'},
  { "verbose",    no_argument,        NULL, 'v'},
  { "version",    no_argument,        NULL, 'V'},
  { NULL,         0,                  NULL, 0}

};

// Global variables
pcap_dumper_t *pcap_dumper;
int ignore_esp;
args_t global_args;

void usage(void) {
  printf("Ipdecap %s, decapsulate ESP, GRE, IPIP packets - Loic Pefferkorn\n", PACKAGE_VERSION);
  printf(
  "Usage\n"
  "    ipdecap [-v] [-l] [-V] -i input.cap -o output.cap [-c esp.conf] [-f <bpf filter>] \n"
  "Options:\n"
  "  -c, --conf     configuration file for ESP parameters (IP addresses, algorithms, ... (see man ipdecap)\n"
  "  -h, --help     this help message\n"
  "  -i, --input    pcap file to process\n"
  "  -o, --output   pcap file with decapsulated data\n"
  "  -f, --filter   only process packets matching the bpf filter\n"
  "  -l, --list     list availables ESP encryption and authentication algorithms\n"
  "  -V, --version  print version\n"
  "  -v, --verbose  verbose\n"
  "\n");
}

void print_version() {
  printf("Ipdecap %s\n", PACKAGE_VERSION);
}

void verbose(const char *format, ...) {

  if (global_args.verbose == true) {
    va_list argp;
    va_start (argp, format);
    vfprintf(stdout, format, argp);
    va_end(argp);
  }
}
/*
 * Parse commande line arguments
 *
 */
void parse_options(int argc, char **argv) {

  int opt = 0;
  int opt_index = 0;

  // Init parameters to default values
  global_args.esp_config_file = NULL;
  global_args.input_file = NULL;
  global_args.output_file = NULL;
  global_args.bpf_filter = NULL;
  global_args.verbose = false;
  global_args.list_algo = false;

  opt = getopt_long(argc, argv, args_str, args_long, &opt_index);
  while(opt != -1) {
    switch(opt) {
      case 'i':
        global_args.input_file = optarg;
        break;
      case 'o':
        global_args.output_file = optarg;
        break;
      case 'c':
        global_args.esp_config_file = optarg;
        break;
      case 'f':
        global_args.bpf_filter = optarg;
        break;
      case 'l':
        global_args.list_algo = true;
        break;
      case 'v':
        global_args.verbose = true;
        break;
      case 'V':
        print_version();
        exit(EXIT_SUCCESS);
      case 'h':
      case '?':
        usage();
        exit(EXIT_FAILURE);
        break;
      case 0:
        if (strcmp("verbose", args_long[opt_index].name) == 0) {
          global_args.verbose = true;
        }
        break;

      default:
        break;
    }
    opt = getopt_long(argc, argv, args_str, args_long, &opt_index);
  }
}




/*
 * Remove IEEE 802.1Q header (virtual lan)
 *
 */
void remove_ieee8021q_header(const u_char *in_payload, const int in_payload_len, pcap_hdr *out_pkthdr, u_char *out_payload) {

  u_char *payload_dst = NULL;
  u_char *payload_src = NULL;

  // Pointer used to shift through source packet bytes
  payload_src = (u_char *) in_payload;
  payload_dst = out_payload;

  // Copy ethernet src and dst
  memcpy(payload_dst, payload_src, 2*sizeof(struct ether_addr));
  payload_src += 2*sizeof(struct ether_addr);
  payload_dst += 2*sizeof(struct ether_addr);

  // Skip ieee 802.1q bytes
  payload_src += VLAN_TAG_LEN;
  memcpy(payload_dst, payload_src, in_payload_len
                                  - 2*sizeof(struct ether_addr)
                                  - VLAN_TAG_LEN);

  // Should I check for minimum frame size, even if most drivers don't supply FCS (4 bytes) ?
  out_pkthdr->len = in_payload_len - VLAN_TAG_LEN;
  out_pkthdr->caplen = in_payload_len - VLAN_TAG_LEN;
}

/*
 * Simply copy non-IP packet
 *
 */
void process_nonip_packet(const u_char *payload, const int payload_len, pcap_hdr *new_packet_hdr, u_char *new_packet_payload) {

  // Copy full packet
  memcpy(new_packet_payload, payload, payload_len);
  new_packet_hdr->len = payload_len;
}




/*
 * For each packet, identify its encapsulation protocol and give it to the corresponding process_xx_packet function
 *
 */
void handle_packets(u_char *bpf_filter, const struct pcap_pkthdr *pkthdr, const u_char *bytes) {

  static int packet_num = 0;
  const struct ether_header *eth_hdr = NULL;
  const struct ip *ip_hdr = NULL;
  struct bpf_program *bpf = NULL;
  struct pcap_pkthdr *in_pkthdr = NULL;
  struct pcap_pkthdr *out_pkthdr = NULL;
  u_char *in_payload = NULL;
  u_char *out_payload = NULL;

  verbose("Processing packet %i\n", packet_num);

  // Check if packet match bpf filter, if given
  if (bpf_filter != NULL) {
    bpf = (struct bpf_program *) bpf_filter;
    if (pcap_offline_filter(bpf, pkthdr, bytes)  == 0) {
      verbose("Packet %i does not match bpf filter\n", packet_num);
      goto exit;
    }
  }

  MALLOC(out_pkthdr, 1, struct pcap_pkthdr);
  MALLOC(out_payload, 65535, u_char);
  memset(out_pkthdr, 0, sizeof(struct pcap_pkthdr));
  memset(out_payload, 0, 65535);

  // Pointer used to shift through source packet bytes
  // updated when vlan header is removed
  // TODO: don't modify source packet

  in_pkthdr = (struct pcap_pkthdr *) pkthdr;
  in_payload = (u_char *) bytes;

  // Copy source pcap metadata
  out_pkthdr->ts.tv_sec = in_pkthdr->ts.tv_sec;
  out_pkthdr->ts.tv_usec = in_pkthdr->ts.tv_usec;
  out_pkthdr->caplen = in_pkthdr->caplen;

  eth_hdr = (const struct ether_header *) in_payload;

  // If IEEE 802.1Q header, remove it before further processing
  if (ntohs(eth_hdr->ether_type) == ETHERTYPE_VLAN) {
      debug_print("%s\n", "\tIEEE 801.1Q header\n");
      remove_ieee8021q_header(in_payload, in_pkthdr->caplen, out_pkthdr, out_payload);

      // Update source packet with the new one without 802.1q header
      memcpy(in_payload, out_payload, out_pkthdr->caplen);
      in_pkthdr->caplen = out_pkthdr->caplen;
      in_pkthdr->len = out_pkthdr->len;

      // Re-read new ethernet type
      eth_hdr = (const struct ether_header *) in_payload;
  }
  // ethertype = *(pkt_in_ptr + 12) << 8 | *(pkt_in_ptr+13);

  if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) {

    // Non IP packet ? Just copy
    process_nonip_packet(in_payload, in_pkthdr->caplen, out_pkthdr, out_payload);
    pcap_dump((u_char *)pcap_dumper, out_pkthdr, out_payload);

  } else {

    // Find encapsulation type
    ip_hdr = (const struct ip *) (in_payload + sizeof(struct ether_header));

    //debug_print("\tIP hlen:%i iplen:%02x protocol:%02x payload_len:%i\n",
      //(ip_hdr->ip_hl *4), ntohs(ip_hdr->ip_len), ip_hdr->ip_p, payload_len);

    switch (ip_hdr->ip_p) {

      case IPPROTO_IPIP:
        debug_print("%s\n", "\tIPPROTO_IPIP");
        process_ipip_packet(in_payload, in_pkthdr->caplen, out_pkthdr, out_payload);
        pcap_dump((u_char *)pcap_dumper, out_pkthdr, out_payload);
        break;

      case IPPROTO_IPV6:
        debug_print("%s\n", "\tIPPROTO_IPV6");
        process_ipv6_packet(in_payload, in_pkthdr->caplen, out_pkthdr, out_payload);
        pcap_dump((u_char *)pcap_dumper, out_pkthdr, out_payload);
        break;

      case IPPROTO_GRE:
        debug_print("%s\n", "\tIPPROTO_GRE\n");
        process_gre_packet(in_payload, in_pkthdr->caplen, out_pkthdr, out_payload);
        pcap_dump((u_char *)pcap_dumper, out_pkthdr, out_payload);
        break;

      case IPPROTO_ESP:
        debug_print("%s\n", "\tIPPROTO_ESP\n");

        if (ignore_esp == 1) {
          verbose("Ignoring ESP packet %i\n", packet_num);
          free(out_pkthdr);
          free(out_payload);
          return;
        }

        process_esp_packet(in_payload, in_pkthdr->caplen, out_pkthdr, out_payload);
        pcap_dump((u_char *)pcap_dumper, out_pkthdr, out_payload);
        break;

      default:
        // Copy not encapsulated/unknown encpsulation protocol packets, like non_ip packets
        process_nonip_packet(in_payload, in_pkthdr->caplen, out_pkthdr, out_payload);
        pcap_dump((u_char *)pcap_dumper, out_pkthdr, out_payload);
        verbose("Copying packet %i: not encapsulated/unknown encapsulation protocol\n", packet_num);

    }
  } // if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP)

  free(out_pkthdr);
  free(out_payload);

  exit: // Avoid several 'return' in middle of code
    packet_num++;
}


int main(int argc, char **argv) {

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *pcap_reader = NULL;
  pcap_dumper = NULL;
  pcap_t *p = NULL;
  struct bpf_program *bpf = NULL;
  ignore_esp = 0;
  int rc;

  parse_options(argc, argv);

  if (global_args.list_algo == true) {
    print_algorithms();
    exit(0);
  }

  verbose("Input file :\t%s\nOutput file:\t%s\nConfig file:\t%s\nBpf filter:\t%s\n",
    global_args.input_file,
    global_args.output_file,
    global_args.esp_config_file,
    global_args.bpf_filter);

  if (global_args.input_file == NULL || global_args.output_file == NULL) {
    usage();
    error("Input and outfile file parameters are mandatory\n");
  }

  pcap_reader = pcap_open_offline(global_args.input_file, errbuf);

  if (pcap_reader == NULL)
    error("Cannot open input file %s: %s", global_args.input_file, errbuf);

  debug_print("snaplen:%i\n", pcap_snapshot(pcap_reader));

  p = pcap_open_dead(DLT_EN10MB, MAXIMUM_SNAPLEN);

  // try to compile bpf filter for input packets
  if (global_args.bpf_filter != NULL) {
    MALLOC(bpf, 1, struct bpf_program);
    verbose("Using bpf filter:%s\n", global_args.bpf_filter);
    if (pcap_compile(p, bpf, global_args.bpf_filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
      error("pcap_compile() %s\n", pcap_geterr(p));
    }
  }
  pcap_dumper = pcap_dump_open(p, global_args.output_file);

  if (pcap_dumper == NULL)
    error("Cannot open output file %s : %s\n", global_args.output_file, errbuf);

  // Try to read ESP configuration file
  if (global_args.esp_config_file != NULL) {
    rc = parse_esp_conf(global_args.esp_config_file);
    switch(rc) {
      case -1:
        warnx("ESP config file: cannot open %s - ignoring ESP packets\n",
          global_args.esp_config_file);
        ignore_esp = 1;
        break;
      case -2:
        warnx("ESP config file: %s is not parsable (missing column ?) - ignoring ESP packets\n",
          global_args.esp_config_file);
        ignore_esp = 1;
        break;
      case 0: // Processing of ESP configuraton file is OK
        break;
    }
  }

  #ifdef DEBUG
    dump_flows();
  #endif

  OpenSSL_add_all_algorithms();

  // Dispatch to handle_packet function each packet read from the pcap file
  pcap_dispatch(pcap_reader, 0, handle_packets, (u_char *) bpf);

  pcap_close(pcap_reader);
  pcap_close(p);
  pcap_dump_close(pcap_dumper);

  EVP_cleanup();

  flows_cleanup();

  return 0;
}
