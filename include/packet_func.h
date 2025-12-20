#ifndef PACKET_FUNC_H
#define PACKET_FUNC_H
#include "headers.h"
#include "structdefs.h"
uint32_t get_tsval(void);
ssize_t send_pkt(int sock, void *pkt, void *rcv_device, socklen_t rcv_dev_len, ssize_t pkt_size);
int build_pkt_ll(struct ifconfig *if_config, struct ll_packet *pkt_ll, char *ip_rcv, unsigned char *dst_mac, uint16_t d_port, uint8_t tcp_flags);
int build_pkt_ip(struct ifconfig *if_config, struct ip_packet *pkt_ip, char *ip_rcv, uint16_t d_port, uint8_t tcp_flags);
void ARP_CONSTRUCT(struct ifconfig *if_config, uint32_t ipv4_recv, struct arp_req *arp_frame);
void eth_packet(struct ethhdr *eth_hdr, unsigned char *dst_mac, unsigned char *src_mac, uint16_t proto);
void ip_packet(struct iphdr *ip_hdr, char *ip_rcv, struct ifconfig *if_config);
void tcp_packet(struct tcphdr *tcp_ptr, struct iphdr *ip_ptr, struct tcpopt *tcp_opts, uint16_t d_port, uint8_t flags);
int tcp_options(struct tcpopt *tcp_opts);
uint16_t csum_tcp(struct iphdr *ip_hdr, struct tcphdr *tcp_hdr, struct tcpopt *tcp_opts);
uint16_t csum_ipv4(struct iphdr *ip_hdr);
int GET_ETH(struct arp_req *arp_frame, struct ifconfig *if_config, unsigned char *dst_mac);

#endif
