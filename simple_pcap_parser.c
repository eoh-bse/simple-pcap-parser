/*
 * pcap-savefile header (32-bit, 4-byte wide)
  +------------------------------+
  |        Magic number          |
  +--------------+---------------+
  |Major version | Minor version |
  +--------------+---------------+
  |      Time zone offset        |
  +------------------------------+
  |     Time stamp accuracy      |
  +------------------------------+
  |       Snapshot length        |
  +------------------------------+
  |   Link-layer header type     |
  +------------------------------+
*/

/*
 * per-packet header in pcap file (32-bit, 4-byte wide)
+----------------------------------------------+
|          Time stamp, seconds value           |
+----------------------------------------------+
|Time stamp, microseconds or nanoseconds value |
+----------------------------------------------+
|       Length of captured packet data         |
+----------------------------------------------+
|   Un-truncated length of the packet data     |
+----------------------------------------------+
*/

#include <arpa/inet.h>
#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

// size, length, offset are in bytes (octets)
#define PCAP_HEADER_LEN 24
#define PCAP_HEADER_WIDTH 4
#define PCAP_MAGIC_NUM 0xa1b2c3d4
#define LINKTYPE_ETHERNET 1
#define PER_PACKET_SIZE_OFFSET 8
#define PER_PACKET_HEADER_WIDTH 4

// Ethernet Frame
#define ETHER_MAC_LEN 6
#define ETHER_ETHERTYPE_LEN 2
#define IPv4 0x0800
#define IPv6 0x86DD

// IP Header
#define MIN_IP_HEADER_SIZE 20 // bytes
#define TCP_PROTOCOL 6        // TCP

#define INIT_PACKET_ARR_CAP 128

static bool debug = false;

static size_t data_packet_count = 0;

typedef struct {
  size_t header;
  size_t payload;
} IpPacketSize;

typedef struct {
  uint8_t tcp_flags;
  uint32_t dest_ip;
  uint32_t tcp_seq_num;
  size_t tcp_payload_size;
  char *tcp_payload;
} Packet;

static Packet *packets;

static void setup(void) {
  packets = malloc(sizeof(Packet) * INIT_PACKET_ARR_CAP);
}

static size_t packet_count = 0;
static size_t packet_cap = INIT_PACKET_ARR_CAP;
static void store_packet(Packet *packet) {
  if (packet_count < packet_cap) {
    packets[packet_count++] = *packet;
    return;
  }

  packet_cap <<= 1;
  packets = realloc(packets, sizeof(Packet) * packet_cap);
  packets[packet_count++] = *packet;
  if (debug)
    fprintf(stdout, "Packet Array Resized to: %lu\n", packet_cap);
}

// The following implementation assumes you are on little endian machine
// TODO: Detect actual machine endianness and call `ntoh` everywhere
static void parse_magic_number(FILE *pcap_file) {
#define PRINT_MSG(endian) fprintf(stdout, "The pcap header is in %s\n", endian);

  uint32_t magic_num;
  fread(&magic_num, PCAP_HEADER_WIDTH, 1, pcap_file);
  if (magic_num == PCAP_MAGIC_NUM) {
    PRINT_MSG("LITTLE ENDIAN");
    return;
  }

  PRINT_MSG("BIG ENDIAN");
}

static void parse_version(FILE *pcap_file) {
  uint16_t version[2];
  fread(version, PCAP_HEADER_WIDTH, 1, pcap_file);
  fprintf(stdout, "Major Version: %u\n", version[0]);
  fprintf(stdout, "Minor Version: %u\n", version[1]);
}

static void parse_snapshot_length(FILE *pcap_file) {
  // skip time zone offset and timestamp accuracy
  fseek(pcap_file, 8L, SEEK_CUR);

  uint32_t snapshot_len;
  fread(&snapshot_len, PCAP_HEADER_WIDTH, 1, pcap_file);
  fprintf(stdout, "Snapshot Length: %u bytes\n", snapshot_len);
}

static void parse_link_header_type(FILE *pcap_file) {
  uint32_t linktype;
  fread(&linktype, PCAP_HEADER_WIDTH, 1, pcap_file);
  fprintf(stdout, "Link-layer header type: %u\n", linktype);

  assert(linktype == LINKTYPE_ETHERNET);
}

static void parse_pcap_header(FILE *pcap_file) {
  parse_magic_number(pcap_file);
  parse_version(pcap_file);
  parse_snapshot_length(pcap_file);
  parse_link_header_type(pcap_file);
}

static size_t parse_per_packet_header(FILE *pcap_file) {
  fseek(pcap_file, PER_PACKET_SIZE_OFFSET, SEEK_CUR);

  uint32_t packet_sizes[2];
  size_t items_read =
      fread(packet_sizes, PER_PACKET_HEADER_WIDTH, 2, pcap_file);
  if (items_read != 2)
    return 0; // done

  // Packet must not be truncated
  bool not_truncated = packet_sizes[0] == packet_sizes[1];
  if (debug && !not_truncated)
    fprintf(stdout, "Captured: %x - %u, Actual: %x - %u\n", packet_sizes[0],
            packet_sizes[0], packet_sizes[1], packet_sizes[1]);

  assert(not_truncated);
  return packet_sizes[0];
}

static size_t parse_mac_addrs(FILE *pcap_file) {
  uint8_t mac_parts[12];
  fread(mac_parts, ETHER_MAC_LEN, 2, pcap_file);

  if (debug) {
    fprintf(stdout, "MAC Source: %x:%x:%x:%x:%x:%x\n", mac_parts[6],
            mac_parts[7], mac_parts[8], mac_parts[9], mac_parts[10],
            mac_parts[11]);
    fprintf(stdout, "MAC Destination: %x:%x:%x:%x:%x:%x\n", mac_parts[0],
            mac_parts[1], mac_parts[2], mac_parts[3], mac_parts[4],
            mac_parts[5]);
  }

  return 12;
}

static size_t parse_ether_type(FILE *pcap_file) {
  // We are assuming no 802.1Q tag
  uint16_t protocol;
  fread(&protocol, ETHER_ETHERTYPE_LEN, 1, pcap_file);

  protocol = ntohs(protocol);
  if (debug)
    fprintf(stdout, "IP Protocol used in the packet: %x\n", protocol);

  assert(protocol == IPv4);

  return ETHER_ETHERTYPE_LEN;
}

static size_t parse_ethernet_frame(FILE *pcap_file) {
  size_t bytes_read = 0;
  bytes_read += parse_mac_addrs(pcap_file);
  bytes_read += parse_ether_type(pcap_file);

  return bytes_read;
}

static uint16_t parse_ip_header_size(FILE *pcap_file) {
  uint8_t ver_and_len;
  fread(&ver_and_len, 1, 1, pcap_file);
  uint16_t len = (uint16_t)(ver_and_len & 0x0f) * 4;
  if (debug)
    fprintf(stdout, "IP packet header length: %u bytes\n", len);

  return len;
}

static uint16_t parse_ip_packet_size(FILE *pcap_file) {
  uint16_t len;
  fread(&len, 2, 1, pcap_file);
  len = ntohs(len);
  if (debug)
    fprintf(stdout, "IP packet length: %u bytes\n", len);

  return len;
}

static void parse_ip_protocol(FILE *pcap_file) {
  uint8_t protocol;
  fread(&protocol, 1, 1, pcap_file);
  assert(protocol == TCP_PROTOCOL);
  if (debug)
    fprintf(stdout, "IP Protocol: TCP\n");
}

static void parse_ips(FILE *pcap_file, Packet *packet) {
  uint32_t ips[2];
  fread(ips, 4, 2, pcap_file);

  if (debug) {
    uint8_t *src_ip = (uint8_t *)&ips[0];
    uint8_t *dest_ip = (uint8_t *)&ips[1];
    fprintf(stdout, "Src IP: %u.%u.%u.%u\n", src_ip[0], src_ip[1], src_ip[2],
            src_ip[3]);
    fprintf(stdout, "Dest IP: %u.%u.%u.%u\n", dest_ip[0], dest_ip[1],
            dest_ip[2], dest_ip[3]);
  }

  packet->dest_ip = ips[1];
}

static void parse_ip_header(FILE *pcap_file, IpPacketSize *size,
                            Packet *packet) {
#define OFFSET_TO_PACKET_SIZE 1
#define OFFSET_TO_PROTOCOL 5
#define OFFSET_TO_SRC_IP 2

  size->header = parse_ip_header_size(pcap_file);
  fseek(pcap_file, OFFSET_TO_PACKET_SIZE, SEEK_CUR); // skip DSCP and ECN
  size->payload = parse_ip_packet_size(pcap_file) - size->header;

  fseek(pcap_file, OFFSET_TO_PROTOCOL, SEEK_CUR); // skip to IP Protocol
  parse_ip_protocol(pcap_file);

  // skip header checksum to get to ip addresses
  fseek(pcap_file, OFFSET_TO_SRC_IP, SEEK_CUR);
  parse_ips(pcap_file, packet);

  // Skip to start of payload. We read 20 bytes so far
  fseek(pcap_file, size->header - MIN_IP_HEADER_SIZE, SEEK_CUR);
}

static uint32_t parse_seq_num(FILE *pcap_file) {
  uint32_t seq_num;
  fread(&seq_num, 4, 1, pcap_file);
  seq_num = ntohl(seq_num);
  if (debug)
    fprintf(stdout, "Sequence Number: %x - %u\n", seq_num, seq_num);

  return seq_num;
}

static size_t parse_tcp_header_size(FILE *pcap_file) {
  uint8_t first_byte;
  fread(&first_byte, 1, 1, pcap_file);
  return (size_t)((first_byte & 0xf0) >> 4) * 4;
}

static uint8_t parse_tcp_flags(FILE *pcap_file) {
  uint8_t flags;
  fread(&flags, 1, 1, pcap_file);
  return flags;
}

static void parse_tcp_packet(FILE *pcap_file, size_t ip_packet_payload_size,
                             Packet *packet) {
#define OFFSET_TO_SEQ_NUM 4
#define OFFSET_TO_DATA_OFFSET 4
#define OFFSET_AFTER_FLAGS 14 // basically offset to "window size"
  fseek(pcap_file, OFFSET_TO_SEQ_NUM, SEEK_CUR);
  packet->tcp_seq_num = parse_seq_num(pcap_file);

  fseek(pcap_file, OFFSET_TO_DATA_OFFSET, SEEK_CUR);
  size_t header_size = parse_tcp_header_size(pcap_file);
  packet->tcp_flags = parse_tcp_flags(pcap_file);
  if (debug)
    fprintf(stdout, "TCP Header Size: %lu bytes, TCP Payload Size: %lu\n",
            header_size, ip_packet_payload_size - header_size);

  fseek(pcap_file, header_size - OFFSET_AFTER_FLAGS, SEEK_CUR);
  packet->tcp_payload_size = ip_packet_payload_size - header_size;
  packet->tcp_payload = malloc(packet->tcp_payload_size);
  fread(packet->tcp_payload, 1, packet->tcp_payload_size, pcap_file);
}

static bool parse_packet(FILE *pcap_file, Packet *packet) {
  size_t packet_size = parse_per_packet_header(pcap_file);
  if (!packet_size)
    return false;

  size_t ether_frame_header_size = parse_ethernet_frame(pcap_file);
  IpPacketSize ip_packet_size;
  parse_ip_header(pcap_file, &ip_packet_size, packet);
  parse_tcp_packet(pcap_file, ip_packet_size.payload, packet);

  // Ethernet imposes 60-byte minimum on packet sizes which add trailer bytes
  // skip trailer bytes
  fseek(pcap_file,
        packet_size - ether_frame_header_size - ip_packet_size.header -
            ip_packet_size.payload,
        SEEK_CUR);

  return true;
}

static int compare_packets(const void *packet0, const void *packet1) {
  const Packet *p0 = packet0;
  const Packet *p1 = packet1;
  if (p0->tcp_seq_num < p1->tcp_seq_num)
    return -1;

  if (p0->tcp_seq_num > p1->tcp_seq_num)
    return 1;

  return 0;
}

static void parse_and_order_packets(FILE *pcap_file) {
#define SYN_ACK_BITS 0x12 // CWR|ECE|URG|ACK|PSH|RST|SYN|FIN - 0b00010010
#define FIN_BIT 1

  fseek(pcap_file, PCAP_HEADER_LEN, SEEK_SET);

  Packet packet;
  packet.tcp_flags = 0;
  while (packet.tcp_flags != SYN_ACK_BITS && parse_packet(pcap_file, &packet))
    ;

  uint32_t receiving_ip = packet.dest_ip;
  fprintf(stdout, "Receiving IP: %x\n", receiving_ip);
  do {
    if (packet.dest_ip != receiving_ip || packet.tcp_payload_size == 0)
      continue;

    store_packet(&packet);
    data_packet_count++;
  } while (!(packet.tcp_flags & FIN_BIT) && parse_packet(pcap_file, &packet));

  qsort(packets, data_packet_count, sizeof(Packet), compare_packets);
  fprintf(stdout, "Parsed: %lu data packets\n", data_packet_count);
}

static void store_data_in_first_http_packet(FILE *output) {
  uint32_t delimiter = htonl(0x0d0a0d0a); // CRLF CRLF
  for (size_t i = 0; i < packets[0].tcp_payload_size; i++) {
    uint32_t four_bytes = *(uint32_t *)&packets[0].tcp_payload[i];
    if ((delimiter ^ four_bytes) == 0) {
      fwrite(&(packets[0].tcp_payload[i + 4]), 1,
             packets[0].tcp_payload_size - i - 3, output);
      return;
    }
  }
}

static void store_data(char *output_path) {
  FILE *output = fopen(output_path, "a");
  assert(output != NULL);

  store_data_in_first_http_packet(output);
  uint32_t seq_num = packets[0].tcp_seq_num;
  for (size_t i = 1; i < data_packet_count; i++) {
    if (packets[i].tcp_seq_num == seq_num)
      continue;

    fwrite(packets[i].tcp_payload, 1, packets[i].tcp_payload_size, output);
    seq_num = packets[i].tcp_seq_num;
  }

  fclose(output);
  fprintf(stdout, "Data was saved to %s\n", output_path);
}

int main(int argc, char *argv[]) {
  if (argc < 3) {
    fprintf(stderr, "No pcap file to parse or output file name was given\n");
    return EXIT_FAILURE;
  }

  setup();

  FILE *pcap_file = fopen(argv[1], "r");
  if (pcap_file == NULL) {
    fprintf(stderr, "Could not open %s: %m\n", argv[1]);
    return EXIT_FAILURE;
  }

  parse_pcap_header(pcap_file);
  parse_and_order_packets(pcap_file);
  assert(packet_count > 0);
  fclose(pcap_file);

  store_data(argv[2]);
}
