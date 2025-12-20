#ifndef IP_FUNC_H
#define IP_FUNC_H
#include "headers.h"
#include "structdefs.h"


void *ip_scan(void *scan_ip_scan);
void *ip_recv(void *scan_ip_args);
int build_pkt_ip(struct ifconfig *if_config, struct ip_packet *pkt_ip, char *ip_rcv, uint16_t d_port, uint8_t tcp_flags);
int data_mgmt_ip(int ip_sock, struct ifconfig *if_config, struct user_def_values *config, void *in_dev, socklen_t rcv_dev_len, uint32_t ip_recv_b, int file_fd, int if_sock, void *if_dev, socklen_t if_dev_len);


#endif
