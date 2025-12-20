#ifndef NETLINK_HANDLE_H
#define NETLINK_HANDLE_H
#include "structdefs.h"

int NETLINK_NLMSG_RD(struct nl_data *nl_data, struct ifconfig *if_config, ssize_t rcv_byte);
int NETLINK_COMM(int sock_nl, struct nl_data *nldata, struct kernel_msg *kern_msg, struct ifconfig *if_config);
int NETLINK_MSG(struct ifconfig *if_config, int sock_nl, int request, struct nl_sock *recv_addr, struct nl_sock *send_addr, struct kernel_msg *kern_msg, struct nl_data *nldata);
int NETLINK_SOCK(struct nl_sock *recv_addr, struct nl_sock *send_addr);
int NETLINK_HANDLE(int request, struct ifconfig *if_config);


#endif
