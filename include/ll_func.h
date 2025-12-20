#ifndef LL_FUNC_H
#define LL_FUNC_H
#include "structdefs.h"
#include "headers.h"
#include "packet_func.h"


void *ll_scan(void *ll_scan);
void *ll_recv(void *ll_args);
int build_pkt_ll(struct ifconfig *if_config, struct ll_packet *pkt_ll, char *ip_rcv, unsigned char *dst_mac, uint16_t d_port, uint8_t tcp_flags);
int data_mgmt_ll(int recv_sock, int scan_sock,struct ifconfig *if_config, struct user_def_values *config, void *rcv_dev, socklen_t rcv_dev_len, uint32_t ip_recv_b, int file_fd);








#endif
