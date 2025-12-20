#ifndef STRUCTDEFS_H
#define STRUCTDEFS_H
#include "headers.h"


struct user_def_values {
  uint16_t d_port;
  char *ip_rcv;
  char *ip_src;
  uint32_t ip_src_bytes;
  int ip_true;
  unsigned char mac_src[ETH_ALEN];
  int mac_true;
  uint8_t tcp_flags;
  uint16_t start_port;
  uint16_t end_port;
  int arp_scan;
  int pfile_true;
  char pfile_name[16];
  uint16_t *pfile_ports;
  int pfile_portnum;
  int pfile_fd;
};

struct nl_data {
  void *nl_rcv;
  void *nl_msg;
  uint32_t nl_msglen;
};

struct kernel_msg {
  struct iovec iov;
  struct msghdr msg;
};

struct nl_sock {
  struct sockaddr_nl sock_addr;
  socklen_t addr_len;
};

struct opt_mss {
  uint8_t mss_size;
  uint8_t len;
  uint16_t mss_val;
}__attribute__((packed));

struct opt_sack {
  uint8_t kind;
  uint8_t len;
}__attribute__((packed));

struct opt_tsval {
  uint8_t kind;
  uint8_t len;
  uint32_t tsval;
  uint32_t echo_r;
}__attribute__((packed));

struct opt_nop {
  uint8_t kind;
}__attribute__((packed));

struct opt_win {
  uint8_t kind;
  uint8_t len;
  uint8_t shift_count;
}__attribute__((packed));

typedef struct {
  struct ifconfig *if_config;
  struct user_def_values *config;
  int eth_sock;
  void *rcv_dev;
  socklen_t rcv_dev_len;
  uint32_t ip_recv_b;
  unsigned char dst_mac[ETH_ALEN];
} ll_scan_args;

typedef struct {
  struct ifconfig *if_config;
  struct user_def_values *config;
  int eth_sock;
  void *rcv_dev;
  socklen_t rcv_dev_len;
  uint32_t ip_recv_b;
  int file_fd;
  unsigned char dst_mac[ETH_ALEN];
} ll_recv_args;


typedef struct {
  int if_sock;
  void *if_dev;
  socklen_t if_dev_len;
  struct ifconfig *if_config;
  struct user_def_values *config;
  int file_fd;
  uint32_t ip_recv_b;
} ip_recv_args;


typedef struct {
  struct ifconfig *if_config;
  struct user_def_values *config;
  int sock;
  void *in_dev;
  socklen_t rcv_dev_len;
  uint32_t ip_recv_b;
} ip_scan_args;

struct tcpopt {
  struct opt_mss mss;
  struct opt_sack sack;
  struct opt_tsval tsval;
  struct opt_nop nop;
  struct opt_win win;
}__attribute__((packed));

struct packet_noopt {
  struct ethhdr eth_hdr;
  struct iphdr ip_hdr;
  struct tcphdr tcp_hdr;
}__attribute__((packed));


struct arp_req {
  struct ethhdr eth_arp_hdr;
  struct arphdr arp_hdr;
  unsigned char arp_sha[ETH_ALEN];
  __be32 arp_sip;
  unsigned char arp_tha[ETH_ALEN];
  __be32 arp_tip;
  unsigned char padding[ARP_PAD_FRAME_END];
} __attribute__((packed));

struct arp_rep {
  unsigned char eth_tha[ETH_ALEN];
  unsigned char eth_sha[ETH_ALEN];
  __be16  eth_type;
  __be16  arp_hw_type;
  __be16  arp_proto_type;
  uint8_t hw_size;
  uint8_t proto_size;
  __be16  opcode;
  unsigned char sha[ETH_ALEN];
  __be32 sip;
  unsigned char tha[ETH_ALEN];
  __be32 tip;
  unsigned char padding[ARP_PAD_FRAME_END];
} __attribute__((packed));

struct ll_packet {
  struct ethhdr eth_hdr;
  struct iphdr ip_hdr;
  struct tcphdr tcp_hdr;
  struct tcpopt tcp_opts;
} __attribute__((packed));

struct ip_packet {
  struct iphdr ip_hdr;
  struct tcphdr tcp_hdr;
  struct tcpopt tcp_opts;
} __attribute__((packed));


struct ifconfig {
  char interface[IFNAMSIZ];
  unsigned char mac[ETH_ALEN];
  unsigned char brd_mac[ETH_ALEN];
  struct in_addr ipv4_addr;
  struct in_addr netmask;
  struct in_addr broadcast;
  struct in_addr gateway;
  int index;
};

struct tcppsd {
  __be32 ip_saddr;
  __be32 ip_daddr;
  uint8_t fixed;
  uint8_t ip_protocol;
  __be16 tcp_seglen;
} __attribute__((packed));


#endif
