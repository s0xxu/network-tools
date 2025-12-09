#define _GNU_SOURCE
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_link.h>
#include <linux/if_addr.h>
#include <linux/types.h>
#include <linux/sockios.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <ctype.h>
#include "include/packetdefs.h"

#define IPV4_ALEN 4
#define ARP_PAD_FRAME_END 18
#define RCVBUF_SIZE 1024 * 1024
#define SNDBUF_SIZE 32 * 1024
#pragma GCC diagnostic ignored "-Waddress-of-packed-member"
 

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
  short index;
};

struct tcppsd {
  __be32 ip_saddr;
  __be32 ip_daddr;
  uint8_t fixed;
  uint8_t ip_protocol;
  __be16 tcp_seglen;
} __attribute__((packed));

uint32_t get_tsval(void) {
    return time(NULL);  
}



int log_port_csv(int file_fd, void *packet, size_t len) {
    if (len < 54) return -1;
       
      struct iphdr *ip = (struct iphdr *)(packet + 14);
      struct tcphdr *tcp = (struct tcphdr *)(packet + 14 + (ip->ihl * 4));
    
      char csv_line[128];
      const char *status = "UNKNOWN";
      uint8_t *tcp_bytes = (uint8_t *)tcp;
      uint8_t flags_byte = tcp_bytes[13];
      if (flags_byte == 0x12) status = "OPEN";
      else if (flags_byte == 0x14) status = "CLOSED";
      else if (flags_byte == 0x04) status = "FILTERED";
    
      int len_written = snprintf(csv_line, sizeof(csv_line),
                                 "%d,%d.%d.%d.%d,%s\n",
                                 ntohs(tcp->source),
                                 (ntohl(ip->saddr) >> 24) & 0xFF,
                                 (ntohl(ip->saddr) >> 16) & 0xFF,
                                 (ntohl(ip->saddr) >> 8) & 0xFF,
                                 ntohl(ip->saddr) & 0xFF,
                                 status);
    
      if ((write(file_fd, csv_line, len_written)) == -1) {
          printf("writing CSV port data FAIL %d %s\n", errno, strerror(errno)); 
          return -1;
      }
      return 0;
}



int NETLINK_NLMSG_RD(struct nl_data *nldata, struct ifconfig *if_config, ssize_t rcv_byte) {
    
  for(struct nlmsghdr *nh_r = (struct nlmsghdr *)nldata->nl_rcv; NLMSG_OK(nh_r, rcv_byte); nh_r = NLMSG_NEXT(nh_r, rcv_byte)) {

    if (nh_r->nlmsg_seq == nh_r->nlmsg_seq) { 
      switch(nh_r->nlmsg_type) {
        case RTM_NEWROUTE:
            struct rtmsg *rtm_r = (struct rtmsg *)NLMSG_DATA(nh_r);    
            int rtm_attr_size = RTM_PAYLOAD(nh_r);
              for (struct rtattr *rta = (struct rtattr *)RTM_RTA(rtm_r); RTA_OK(rta, rtm_attr_size);rta = RTA_NEXT(rta, rtm_attr_size)) { 
                void *data_rtm = NULL;
                  switch(rta->rta_type) {
                    case RTA_GATEWAY:
                        data_rtm = RTA_DATA(rta);
                        memcpy(&if_config->gateway.s_addr, data_rtm, sizeof(struct in_addr));
                        if_config->gateway.s_addr = htonl(if_config->gateway.s_addr);
                        break;
                    case RTA_OIF:
                        data_rtm = RTA_DATA(rta);
                        memcpy(&if_config->index, data_rtm, sizeof(int));
                        break;
                    case RTA_PREFSRC:
                        data_rtm = RTA_DATA(rta);
                        memcpy(&if_config->ipv4_addr.s_addr, data_rtm, sizeof(struct in_addr));
                        break;
                    default:
                        break;
                            } 
                          }
            break; //case NEWROUTE end here
        case RTM_NEWLINK:
          int ifi_flags = IFF_BROADCAST | IFF_UP | IFF_RUNNING | IFF_MULTICAST;
          struct ifinfomsg *ifi = (struct ifinfomsg *)NLMSG_DATA(nh_r);
          int attr_size = IFLA_PAYLOAD(nh_r);
            if (ifi->ifi_flags & ifi_flags) {
              for (struct rtattr *rta = (struct rtattr *)IFLA_RTA(ifi); RTA_OK(rta, attr_size); rta = RTA_NEXT(rta, attr_size)) {
                void *data_ifl = NULL;
                  switch(rta->rta_type) {
                    case IFLA_ADDRESS:
                        data_ifl = RTA_DATA(rta);                                   
                        memcpy(&if_config->mac, data_ifl, ETH_ALEN);
                        break;
                    case IFLA_BROADCAST:
                        data_ifl = RTA_DATA(rta);
                        memcpy(&if_config->brd_mac, data_ifl, ETH_ALEN);
                        break;  
                    default:
                        break;    
                  }                       
              } 
            }
            break; //case newlink end
        case RTM_NEWADDR:
            break;            
        case NLMSG_ERROR:    
          struct nlmsgerr *nh_err = (struct nlmsgerr *)NLMSG_DATA(nh_r);
            if (nh_err->error == 0) {
                printf("ACK KERNEL\n");
                break;
            } 
            if (nh_err->error < 0) {
                printf("netlink header return ERR %d %s\n", nh_err->error, strerror(nh_err->error));
                break;
            }
            break;                     
        case NLMSG_DONE:
            printf("NLMSG_DONE\n");
            free(nldata->nl_rcv);
            return 0;
        default:
            break;
      }
    }
  }  
  return 0;
}




int NETLINK_COMM(int sock_nl, struct nl_data *nldata, struct kernel_msg *kern_msg, struct ifconfig *if_config) {

    ssize_t netlink_sent = send(sock_nl, nldata->nl_msg, nldata->nl_msglen, 0);  
        if (netlink_sent == -1) {
            printf("socket netlink returned -1%d %s\n", errno, strerror(errno));
            close(sock_nl);
            free(nldata->nl_msg);
            free(nldata->nl_rcv);
            return -1;
        }

        if (netlink_sent == 0) {
            printf("socket netlink received 0 bytes\n");
            close(sock_nl);
            free(nldata->nl_rcv);
            free(nldata->nl_msg);
            return -1;
        }

       if (netlink_sent > 0) {

        free(nldata->nl_msg);  

          while(1) {
            ssize_t rcv_byte = recvmsg(sock_nl, &kern_msg->msg, 0);   
                if (rcv_byte == -1) {
                    printf("socket netlink returned -1%d %s\n", errno, strerror(errno));
                    close(sock_nl);
                    free(nldata->nl_rcv);
                    return -1;
                }

                if (rcv_byte >= 0) {
                  if ((NETLINK_NLMSG_RD(nldata, if_config, rcv_byte)) == 0) {
                      free(nldata->nl_rcv);
                      close(sock_nl);
                      return 0;
                  }
                  return -1;  
                }
          }
       }
}




int NETLINK_MSG(struct ifconfig *if_config, int sock_nl, int request, struct nl_sock *recv_addr, struct nl_sock *send_addr, struct kernel_msg *kern_msg, struct nl_data *nldata) {
      nldata->nl_msglen = 0;
      struct nlmsghdr *nlh;    
      pid_t pid = getpid();   
      //build requests
    switch(request) {
      case RTM_GETLINK:
            nldata->nl_msg = malloc(NLMSG_LENGTH(sizeof(struct ifinfomsg)));
              if (nldata->nl_msg == NULL) {
                  perror("MALLOC IFINFOMSG FAIL\n");
                  close(sock_nl);
                  return -1;
              }
            nlh = (struct nlmsghdr *)nldata->nl_msg; 
            nldata->nl_msglen = NLMSG_LENGTH(sizeof(struct ifinfomsg));
            struct ifinfomsg *ifi = (struct ifinfomsg *)(nldata->nl_msg + NLMSG_ALIGN(sizeof(struct ifinfomsg))); 
            memset(ifi, 0, sizeof(struct ifinfomsg)); 
            ifi->ifi_family = AF_UNSPEC;
            ifi->ifi_index = if_config->index;
            nlh->nlmsg_flags = NLM_F_REQUEST;
              break;

      case RTM_GETADDR:
            nldata->nl_msg = malloc(NLMSG_LENGTH(sizeof(struct ifaddrmsg))); 
              if (nldata->nl_msg == NULL) {
                  perror("MALLOC IFADDRMSG FAIL\n");
                  close(sock_nl);
                  return -1;
              } 
            nlh = (struct nlmsghdr *)nldata->nl_msg;   
            nldata->nl_msglen = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
            struct ifaddrmsg *ifa = (struct ifaddrmsg *)(nldata->nl_msg + NLMSG_ALIGN(sizeof(struct ifaddrmsg)));
            memset(ifa, 0, sizeof(struct ifaddrmsg)); 
            ifa->ifa_index = if_config->index;
            ifa->ifa_family = AF_UNSPEC;  
              break;

      case RTM_GETROUTE:
            nldata->nl_msg = malloc(NLMSG_LENGTH(sizeof(struct rtmsg)));           
              if (nldata->nl_msg == NULL) {
                    perror("MALLOC RTMSG FAIL\n");
                    close(sock_nl);
                    return -1;
              }
            nlh = (struct nlmsghdr *)nldata->nl_msg; 
            nldata->nl_msglen  = NLMSG_LENGTH(sizeof(struct rtmsg));
            struct rtmsg *rtm = (struct rtmsg *)(nldata->nl_msg + NLMSG_ALIGN(sizeof(struct rtmsg)));
            memset(rtm, 0, sizeof(struct rtmsg)); 
            rtm->rtm_family = AF_INET;
            rtm->rtm_table = RT_TABLE_MAIN;
            nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
              break;

      case RTM_GETNEIGH:
            nldata->nl_msg = malloc(NLMSG_LENGTH(sizeof(struct ndmsg)));
              if (nldata->nl_msg == NULL) {
                    perror("MALLOC NDMSG FAIL\n");
                    close(sock_nl);
                    return -1;
              }
            nlh = (struct nlmsghdr *)nldata->nl_msg; 
            nldata->nl_msglen = NLMSG_LENGTH(sizeof(struct ndmsg));
            struct ndmsg *ndm = (struct ndmsg *)(nldata->nl_msg + NLMSG_ALIGN(sizeof(struct ndmsg)));     
            memset(ndm, 0, sizeof(struct ndmsg));
            
              break;
      default:
          printf("INVALID REQ\n");
          return -1;
          break;
    }
      nlh->nlmsg_len = nldata->nl_msglen;  
      nlh->nlmsg_type = request;

      nlh->nlmsg_seq = pid;
      nlh->nlmsg_pid = pid;

    
    //recv message
      nldata->nl_rcv = malloc(NLMSG_SPACE(RCVBUF_SIZE));
              if (nldata->nl_rcv == NULL) {
                   perror("MALLOC FAIL RECV NL BUFF\n");
                   free(nldata->nl_msg);
                   close(sock_nl);
                   return -1;
              }
      memset(nldata->nl_rcv, 0, NLMSG_SPACE(RCVBUF_SIZE));
    //kernel return iovec struct
      memset(&kern_msg->iov, 0, sizeof(struct iovec));
      kern_msg->iov.iov_base = nldata->nl_rcv;
      kern_msg->iov.iov_len = NLMSG_SPACE(RCVBUF_SIZE);

      memset(&kern_msg->msg, 0, sizeof(struct msghdr));
      kern_msg->msg.msg_name = &recv_addr->sock_addr;
      kern_msg->msg.msg_namelen = recv_addr->addr_len; 
      kern_msg->msg.msg_iov = &kern_msg->iov;
      kern_msg->msg.msg_iovlen = 1;
    
      return 0;
}



int NETLINK_SOCK(struct nl_sock *recv_addr, struct nl_sock *send_addr) {

    pid_t pid = getpid();
    int sockopt_true = 1;
    int snd_size = SNDBUF_SIZE;
    int rcv_size = RCVBUF_SIZE;
    int sock_nl = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

      if (sock_nl == -1) {
        printf("failed NETLINK sock setup %d %s\n", errno, strerror(errno));
        close(sock_nl);
        return -1;
      }

  //handle communication with kernel
      if (setsockopt(sock_nl, SOL_SOCKET, SO_RCVBUF, &rcv_size, sizeof(SO_RCVBUF)) == -1) {
        printf("setsockopt netlink sock SO_RECVBUFF returned %d %s\n", errno, strerror(errno));
        return -1;
      }

      if (setsockopt(sock_nl, SOL_SOCKET, SO_SNDBUF, &snd_size, sizeof(SO_SNDBUF)) == -1) {
        printf("setsockopt netlink sock SO_SNDBUFF returned %d %s\n", errno, strerror(errno));
        close(sock_nl);
        return -1;
      }

      if (setsockopt(sock_nl, SOL_NETLINK, NETLINK_EXT_ACK, &sockopt_true, sizeof(sockopt_true)) == -1) {
          printf("setsockopt netlink sock netlink_exit_ack returned %d %s\n", errno, strerror(errno));
          close(sock_nl);
          return -1;
      }

      if (setsockopt(sock_nl, SOL_NETLINK, NETLINK_GET_STRICT_CHK, &sockopt_true, sizeof(sockopt_true)) == -1) {
          printf("setsockopt netlink sock netlink_exit_ack returned %d %s\n", errno, strerror(errno));
          close(sock_nl);
          return -1;
      } //receive and send socket structures
      memset(&recv_addr->sock_addr, 0, sizeof(struct sockaddr_nl));
      recv_addr->addr_len = sizeof(recv_addr->sock_addr);


      memset(&send_addr->sock_addr, 0, sizeof(struct sockaddr_nl));
      send_addr->addr_len = sizeof(send_addr->sock_addr);
      send_addr->sock_addr.nl_family = AF_NETLINK;
      send_addr->sock_addr.nl_pid = pid;
      send_addr->sock_addr.nl_groups = 0;

        if (bind(sock_nl, (struct sockaddr *) &send_addr->sock_addr, send_addr->addr_len) == -1) {
          printf("failed bind sockaddr_nl to netlink sock %d %s\n", errno, strerror(errno));
          close(sock_nl);
          return -1;  
        }
      return sock_nl;
}



int NETLINK_HANDLE(int request, struct ifconfig *if_config) {
  struct nl_sock recv_addr, send_addr;
  struct kernel_msg kern_msg;
  struct nl_data nldata;
  nldata.nl_msg = NULL; 
  nldata.nl_rcv = NULL;  
  int sock_nl = NETLINK_SOCK(&recv_addr, &send_addr);

      if (sock_nl == -1) { 
          perror("NETLINK SOCK SETUP\n"); 
          close(sock_nl); 
          return -1;
      } 
    
      if ((NETLINK_MSG(if_config, sock_nl, request, &recv_addr, &send_addr, &kern_msg, &nldata)) == -1) {
          perror("NETLINK MSG\n");
          close(sock_nl);
          free(nldata.nl_rcv);
          free(nldata.nl_msg);
          return -1;  
      } 

      if ((NETLINK_COMM(sock_nl, &nldata, &kern_msg, if_config)) == -1) { //RDMSG HANDLED HERE
          perror("NETLINK COMM\n");
          close(sock_nl);
          free(nldata.nl_rcv);
          free(nldata.nl_msg);
          return -1;  
      }

return 0;
//struct ifconfig *if_config, int sock_nl ,int request, struct nl_sock *recv_addr, struct nl_sock *send_addr,struct kernel_msg *kern_msg, void *recv_nl
}



int GET_ETH(struct arp_req *arp_frame, struct ifconfig *if_config, unsigned char *dst_mac) {
  int arp_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
  if (arp_sock == -1) {
    printf("interface socket %d %s\n", errno, strerror(errno));
    exit(EXIT_FAILURE);
  }
  struct sockaddr_ll arp_req_addr = {0};
  socklen_t arp_req_addr_len = sizeof(arp_req_addr);
  arp_req_addr.sll_family = AF_PACKET;
  arp_req_addr.sll_ifindex = if_config->index;  
  memset(arp_req_addr.sll_addr, 0, sizeof(arp_req_addr.sll_addr));
  struct sockaddr_ll arp_rep_addr = {0};
  socklen_t arp_rep_addr_len = sizeof(arp_rep_addr);

  struct arp_rep arp_rep_frame;

  ssize_t ARP_REQ_LEN = 60;
  ssize_t arp_req_bytes = sendto(arp_sock, arp_frame, ARP_REQ_LEN, 0, (struct sockaddr *) &arp_req_addr, arp_req_addr_len);
  if (arp_req_bytes == -1) {
     printf("Failed to send to arp_sock, returning with err %d %s\n", errno, strerror(errno));
     return -1;
  }
  if (arp_req_bytes != ARP_REQ_LEN) {
    perror("partial write, error in sendto function to arp_sock\n");
    return -1;
  }
  if (arp_req_bytes == ARP_REQ_LEN) {
    while(1) {
        ssize_t arp_rep_bytes = recvfrom(arp_sock, &arp_rep_frame, ARP_REQ_LEN, 0, (struct sockaddr *) &arp_rep_addr, &arp_rep_addr_len);
        if (arp_rep_bytes == -1) {
           printf("recvfrom arp_sock ERR%d %s\n", errno, strerror(errno)); 
           return -1;
        } 
        if (arp_rep_bytes != ARP_REQ_LEN) {
           perror("partial read, err in recvfrom func to arp_sock\n");
        }
      if (arp_rep_bytes == ARP_REQ_LEN) {
        if (arp_rep_frame.tip == if_config->ipv4_addr.s_addr) {
            memcpy(dst_mac, &arp_rep_frame.eth_sha, ETH_ALEN);
            return 0;
        }
      }
    }
  }
  return -1;
}



struct ifreq ifconf_name(struct ifreq ifr_conf, struct ifreq ifr_list) {
  memcpy(&ifr_conf.ifr_name, ifr_list.ifr_name, IFNAMSIZ); // FOR IP
  ifr_conf.ifr_name[IFNAMSIZ - 1] = '\0';
  return ifr_conf;
}

int check_if_flags(struct ifreq ifr_conf) {

  if ((ifr_conf.ifr_flags & IFF_UP) && (ifr_conf.ifr_flags & IFF_RUNNING) &&
      (ifr_conf.ifr_flags & IFF_BROADCAST)) { // Check device capabilities //
    if ((!(ifr_conf.ifr_flags & IFF_NOARP)) &&
        (!(ifr_conf.ifr_flags & IFF_LOOPBACK))) {
      printf("%s Meets requirements for ARP/ICMP scanning\n",
             ifr_conf.ifr_name);
      return 0;
    } else {
      printf("Interface: %s is has LOOPBACK or NOARP flag set, returning\n",
             ifr_conf.ifr_name);
      return -1;
    }
  } else {
    printf(
        "Interface: %s does not meet the flags for ARP scanning, returning\n",
        ifr_conf.ifr_name);
    return -1;
  }
}

int if_dev(struct ifconfig *if_config) {
  int if_sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (if_sock == -1) {
    printf("interface socket %d %s\n", errno, strerror(errno));
    exit(EXIT_FAILURE);
  }

  char buffer[2048]; // Buffer for interfaces
  struct ifconf ifc; // ifconf struct
  ifc.ifc_len = sizeof(buffer);
  ifc.ifc_buf = buffer;
  struct ifreq *ifr_list = ifc.ifc_req;

  if (ioctl(if_sock, SIOCGIFCONF, &ifc) == -1) {
    printf("SIOCGIFCONF: %d %s", errno, strerror(errno));
    exit(EXIT_FAILURE);
  }

  int num_interfaces = ifc.ifc_len / sizeof(struct ifreq);

  struct ifreq ifr_conf = {0}, ifr_mac = {0}, ifr_ip = {0}, ifr_broadcast = {0},
               ifr_netmasq = {0}; // different unions different purposes
  for (int i = 0; i < num_interfaces; i++) {
    
    ifr_list[i].ifr_name[IFNAMSIZ - 1] = '\0';

    ifr_netmasq = ifconf_name(ifr_netmasq, ifr_list[i]);
    ifr_broadcast = ifconf_name(ifr_broadcast, ifr_list[i]);
    ifr_ip = ifconf_name(ifr_ip, ifr_list[i]);
    ifr_conf = ifconf_name(ifr_conf, ifr_list[i]);
    ifr_mac = ifconf_name(ifr_mac, ifr_list[i]);

    if (ioctl(if_sock, SIOCGIFFLAGS, &ifr_conf) == -1) { // Flags
      printf("IOCTL SIOCGIFFLAGS: %d %s", errno, strerror(errno));
      exit(EXIT_FAILURE);
    } else {
      if (check_if_flags(ifr_conf) == 0) {
        if (ioctl(if_sock, SIOCGIFHWADDR, &ifr_mac) ==
            -1) { // Get hardware address
          printf("IOCTL SIOCGIFHWADDR: %d %s", errno, strerror(errno));
          exit(EXIT_FAILURE);
        } else {
          if (ioctl(if_sock, SIOCGIFADDR, &ifr_ip) == -1) { // IPV4
            printf("IOCTL SIOCGIFADDR: %d %s", errno, strerror(errno));
            exit(EXIT_FAILURE);
          }
          if (ioctl(if_sock, SIOCGIFBRDADDR, &ifr_broadcast) == -1) {
            printf("IOCTL SIOCGIFDSTADDR: %d %s", errno, strerror(errno));
            exit(EXIT_FAILURE);
          } 
          if (ioctl(if_sock, SIOCGIFNETMASK, &ifr_netmasq) == -1) {
            printf("IOCTL SIOCGIFNETMASK: %d %s", errno, strerror(errno));
            exit(EXIT_FAILURE);
          }
          if (ioctl(if_sock, SIOCGIFINDEX, &ifr_conf) == -1) {
            printf("IOCTL SIOCIFINDEX: %d %s", errno, strerror(errno));
            exit(EXIT_FAILURE);
          }
          if_config->ipv4_addr.s_addr = htonl((uint64_t)ifr_ip.ifr_ifru.ifru_data >> 32);
          if_config->netmask.s_addr = htonl((uint64_t)ifr_netmasq.ifr_ifru.ifru_data >> 32);
          if_config->broadcast.s_addr = htonl((uint64_t)ifr_broadcast.ifr_ifru.ifru_data >> 32);
          memcpy(&if_config->interface, &ifr_conf.ifr_ifrn.ifrn_name, IFNAMSIZ);
          if_config->interface[IFNAMSIZ - 1] = '\0';
          memcpy(&if_config->index, &ifr_conf.ifr_ifru.ifru_ivalue, sizeof(int));
          memcpy(&if_config->mac, &ifr_mac.ifr_ifru.ifru_hwaddr.sa_data, ETH_ALEN);
          close(if_sock);
          return 0;
        }
      } else {
        printf("Incompatible flags for ARP/ICMP with %s, flags are %hx, "
               "exiting, iterating over next conf\n",
               ifr_conf.ifr_name, ifr_conf.ifr_flags);
      }
    }
  }
  return -1;
}

uint16_t csum_ipv4(struct iphdr *ip_hdr) {

  uint32_t sum = 0;

  uint16_t *word_list = (uint16_t *)ip_hdr;
  int num_words = (ip_hdr->ihl * 4) / 2;

  for (int i = 0; i < num_words; i++) {
    sum += word_list[i];
  }

  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }
  return (uint16_t)~sum;
}

uint16_t csum_tcp(struct iphdr *ip_hdr, struct tcphdr *tcp_hdr, struct tcpopt *tcp_opts) {
    uint16_t data_size = 0;
    int tcp_chkdata_s = sizeof(struct tcppsd) + sizeof(struct tcphdr) + sizeof(struct tcpopt) + data_size;     
    uint16_t tcp_seg = (tcp_hdr->doff * 4) + data_size;
    uint32_t sum = 0; 
     
    struct tcppsd tcp_psd_hdr;

    memcpy(&tcp_psd_hdr.ip_saddr, &ip_hdr->saddr, IPV4_ALEN);
    memcpy(&tcp_psd_hdr.ip_daddr, &ip_hdr->daddr, IPV4_ALEN);
    tcp_psd_hdr.tcp_seglen = htons(tcp_seg);
    tcp_psd_hdr.ip_protocol = IPPROTO_TCP;
    tcp_psd_hdr.fixed = 0x00;

          uint16_t *psd_words = (uint16_t *)&tcp_psd_hdr;
            for (int i = 0;i < (sizeof(struct tcppsd) / 2);i++) {
              sum += ntohs(psd_words[i]);
              tcp_chkdata_s - 2;
            }
          uint16_t *hdr_words = (uint16_t*)tcp_hdr; 
            for (int i = 0;i < (sizeof(struct tcphdr) / 2);i++) {
              sum += ntohs(hdr_words[i]);
              tcp_chkdata_s - 2;
            }
          uint16_t *opt_words = (uint16_t*)tcp_opts;
            for (int i = 0;i < (sizeof(struct tcpopt) / 2 );i++) {
              sum += ntohs(opt_words[i]);
              tcp_chkdata_s - 2;
            }
            if (tcp_chkdata_s == 1) {
              uint8_t word = 0x00 >> 8;
              sum += word;
            } 
             
            while (sum >> 16) {
                sum = (sum & 0XFFFF) + (sum >> 16);
            }
            return (uint16_t)~sum;
}



void eth_packet(struct ethhdr *eth_hdr, unsigned char *dst_mac, unsigned char *src_mac, uint16_t proto) {

  memcpy(&eth_hdr->h_dest, dst_mac, ETH_ALEN);
  memcpy(&eth_hdr->h_source, src_mac, ETH_ALEN);
  eth_hdr->h_proto = htons(proto);
  return;

}
void ip_packet(struct iphdr *ip_hdr, char *ip_rcv, struct ifconfig *if_config) {
	
	uint8_t dscp = 0;
	uint8_t dscp_cs1 = 8;
    	uint8_t dscp_af11 = 10;
        uint16_t df = 0x4000;	
    	ip_hdr->ihl = 5;
    	ip_hdr->version = IPVERSION;
    	uint8_t ecn = 0;
    	ip_hdr->tos = (dscp << 2) | ecn;
        ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + 20);
    	ip_hdr->id = htons(0 + (rand() & 28232));
    	ip_hdr->frag_off = htons(df);
    	ip_hdr->ttl = 64;
    	ip_hdr->protocol = 6; // TCP
    	ip_hdr->check = 0;
      memcpy(&ip_hdr->saddr, &if_config->ipv4_addr.s_addr, IPV4_ALEN);   
    	if (inet_pton(AF_INET, ip_rcv, &ip_hdr->daddr) == -1) {
        printf("INET_PTON src%d %s\n", errno, strerror(errno));
        exit(EXIT_FAILURE);
      }
        
    	ip_hdr->check = csum_ipv4(ip_hdr);
    	return;
}

void tcp_packet(struct tcphdr *tcp_ptr, struct iphdr *ip_ptr, struct tcpopt *tcp_opts, uint16_t d_port, uint8_t flags) {

    uint8_t *tcp_bytes = (uint8_t *)tcp_ptr;
    uint16_t source_port = 1024 + (rand() % 28232);
    tcp_ptr->source = htons(source_port);
    tcp_ptr->dest = htons(d_port);
    tcp_ptr->seq = htonl(rand());
    tcp_ptr->ack_seq = 0;
    tcp_ptr->res1 = 0;
    tcp_ptr->doff = 10;
    tcp_bytes[13] = flags;
  	
    tcp_ptr->window = htons(64240);
    tcp_ptr->check = htons(0);
    tcp_ptr->urg_ptr = 0;
    tcp_ptr->check = htons(csum_tcp(ip_ptr, tcp_ptr, tcp_opts));

    return;
    
}

int tcp_options(struct tcpopt *tcp_opts) {

    tcp_opts->mss.mss_size = 0x02;
    tcp_opts->mss.len = 0x04;
    tcp_opts->mss.mss_val = htons(0x05b4);
    tcp_opts->sack.kind = 0x04;
    tcp_opts->sack.len = 0x02;
    tcp_opts->tsval.kind = 0x08;
    tcp_opts->tsval.len = 0x0a;
    tcp_opts->tsval.tsval = htonl(get_tsval());
    tcp_opts->tsval.echo_r = 0x00000000;
    tcp_opts->nop.kind = 0x01;
    tcp_opts->win.kind = 0x03;
    tcp_opts->win.len = 0x03;
    tcp_opts->win.shift_count = 0x0a;
    return 0; 
}

int iplayer_sock(struct sockaddr_in *in_dev, uint32_t ip) {
  if (in_dev != NULL) {
    int header_val = 1;
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
            if (sock == -1) {
                printf("SOCK FD: %d %s\n", errno, strerror(errno));
                exit(EXIT_FAILURE);
            }
            if ((setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &header_val, sizeof(header_val))) == -1) {
                printf("SETSOCKOPT IPPROTO_IP: %d %s\n", errno, strerror(errno));
                exit(EXIT_FAILURE);   
            }
          memset(in_dev, 0, sizeof(struct sockaddr_in));
          in_dev->sin_addr.s_addr = htonl(ip);
          in_dev->sin_family = AF_INET;   
        return sock;
      }
      return -1;
}


int linklayer_sock(struct sockaddr_ll *ll_dev, short interface) {
      int buff_size = 65535;
    	if (ll_dev != NULL) {
        int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
          if (sock == -1) {
            printf("SOCK FD: %d %s\n", errno, strerror(errno));
            exit(EXIT_FAILURE);
          }

        
        ll_dev->sll_family = AF_PACKET;
    	  ll_dev->sll_ifindex = interface;
        ll_dev->sll_protocol = htons(ETH_P_ALL);
        socklen_t ll_dev_len = sizeof(*ll_dev);
        memset(ll_dev->sll_addr, 0, sizeof(ll_dev->sll_addr));
            if (bind(sock, (struct sockaddr *)ll_dev, ll_dev_len) == -1) {
                printf("BIND SOCK FD LINK LAYER: %d %s\n", errno, strerror(errno));
                exit(EXIT_FAILURE);             
            }
        return sock;
      }
      return -1;
}

int create_file() {
  char time_buffer[20];
  time_t now = time(NULL);
  struct tm *tm_info = localtime(&now);
  strftime(time_buffer, sizeof(time_buffer), "%Y%m%d_%H%M%S", tm_info);
  int file_fd = open(time_buffer, O_CREAT | O_RDWR);
  if (file_fd == -1) {
    printf("error in file creation fd %d %s\n", errno, strerror(errno));
    return -1;
  }
  return file_fd;
}


ssize_t send_pkt(int sock, void *pkt, void *rcv_device, socklen_t rcv_dev_len, ssize_t pkt_size) {
      
      ssize_t sent_bytes_pkt = sendto(sock, pkt, pkt_size, 0, (struct sockaddr *)rcv_device, rcv_dev_len);
          if (sent_bytes_pkt == -1) { 
              printf("sendto %d %s\n", errno, strerror(errno));
              return sent_bytes_pkt;
          }
          if (sent_bytes_pkt == 0) { 
              perror("sent_bytes 0, no data sent\n");
              return sent_bytes_pkt;
          } 
          if (sent_bytes_pkt == pkt_size) { 
              return sent_bytes_pkt;
          }  
}



int build_pkt_ll(struct ifconfig *if_config, struct ll_packet *pkt_ll, char *ip_rcv, unsigned char *dst_mac, uint16_t d_port, uint8_t tcp_flags) {
  
      tcp_options(&pkt_ll->tcp_opts); 
      eth_packet(&pkt_ll->eth_hdr, dst_mac, if_config->mac, ETH_P_IP);
	    ip_packet(&pkt_ll->ip_hdr, ip_rcv, if_config);
	    tcp_packet(&pkt_ll->tcp_hdr, &pkt_ll->ip_hdr, &pkt_ll->tcp_opts, d_port, tcp_flags);
      return 0;  
      
}
int build_pkt_ip(struct ifconfig *if_config, struct ip_packet *pkt_ip, char *ip_rcv, uint16_t d_port, uint8_t tcp_flags) {
      tcp_options(&pkt_ip->tcp_opts); 
  	  ip_packet(&pkt_ip->ip_hdr, ip_rcv, if_config);
	    tcp_packet(&pkt_ip->tcp_hdr, &pkt_ip->ip_hdr, &pkt_ip->tcp_opts, d_port, tcp_flags);
      return 0;
}

void ARP_CONSTRUCT(struct ifconfig *if_config, uint32_t ipv4_recv, struct arp_req *arp_frame) {
    
    eth_packet(&arp_frame->eth_arp_hdr, if_config->brd_mac, if_config->mac, ETH_P_ARP);
	  arp_frame->arp_hdr.ar_hrd = htons(ARPHRD_ETHER);
	  arp_frame->arp_hdr.ar_pro = htons(ETH_P_IP);
	  arp_frame->arp_hdr.ar_hln = ETH_ALEN;
	  arp_frame->arp_hdr.ar_pln = IPV4_ALEN;
	  arp_frame->arp_hdr.ar_op = htons(ARPOP_REQUEST);
	  memcpy(&arp_frame->arp_sha, if_config->mac, ETH_ALEN);
    arp_frame->arp_sip = if_config->ipv4_addr.s_addr;
	  memset(&arp_frame->arp_tha, 0, ETH_ALEN);
    arp_frame->arp_tip = htonl(ipv4_recv);
    memset(&arp_frame->padding, 0, ARP_PAD_FRAME_END);
	  return;

}
int arg_handle(int argc, char *argv[], struct user_def_values *config) {

    memset(config, 0, sizeof(struct user_def_values));
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], USER_PORTS) == 0) {

            if (i + 1 >= argc) {
                fprintf(stderr, "Error: %s requires an argument (e.g., 443-448)\n", USER_PORTS);
                return -1;
            }
	    if (sscanf(argv[i + 1], "%hu-%hu", &config->start_port, &config->end_port) == 2) {
				if (config->start_port > config->end_port) {
                			fprintf(stderr, "Error: Start port cannot be greater than end port\n");
                			return -1;
            			}
               		i++;
			continue;
            } else if (sscanf(argv[i + 1], "%hu", &config->start_port) == 1) {
			config->end_port = 0;
				if (config->start_port > 65535 || config->end_port > 65535) {
                			fprintf(stderr, "Error: Port numbers must be between 0-65535\n");
                			return -1;
            			}
			i++;
            } else {
            	fprintf(stderr, "Error: No argument provided\n");
	    }
	     
	    
        }
        else if (strcmp(argv[i], USER_IP) == 0) {

            if (i + 1 >= argc) {
                fprintf(stderr, "Error: %s requires an IP address argument\n", USER_IP);
                return -1;
            }
            

            if (strlen(argv[i + 1]) > 17) { 
                fprintf(stderr, "Error: Invalid IP address format\n");
                return -1;
            } 
            config->ip_rcv = argv[i + 1];
            i++;
        }
        else if (strcmp(argv[i], USER_PORTLIST) == 0) {

            if (i + 1 >= argc) {
                fprintf(stderr, "Error: %s requires a port list argument\n", USER_PORTLIST);
                return -1;
            }
            
            if (strlen(argv[i + 1]) >= sizeof(config->pfile_name)) {
                fprintf(stderr, "Error: Port list too long (max %zu characters)\n", 
                       sizeof(config->pfile_name) - 1);
                return -1;
            }
            	config->pfile_true = 1;
            	strncpy(config->pfile_name, argv[i + 1], sizeof(config->pfile_name) - 1);
            	config->pfile_name[sizeof(config->pfile_name) - 1] = '\0';
	    	config->pfile_fd = open(config->pfile_name, O_RDONLY, 0);
	
	    		if (config->pfile_fd == -1) {
				printf("port file open err %d %s", errno, strerror(errno));
				return -1;
	    		}

			char port_buff[6];
			config->pfile_ports = malloc(4096);
	    		FILE *fp = fdopen(config->pfile_fd, "r");	

				while(fgets(port_buff, sizeof(port_buff), fp)) {
					uint16_t port_value = (uint16_t)atoi(port_buff);
						if (port_value != 0) {
							config->pfile_ports[config->pfile_portnum] = port_value;
							config->pfile_portnum += 1;
						}
				}
				fclose(fp);
				close(config->pfile_fd);
            		i++;
        }
        else if (strcmp(argv[i], USER_FLAGS) == 0) {

            if (i + 1 >= argc) {
                fprintf(stderr, "Error: %s requires a flag value\n", USER_FLAGS);
                return -1;
            }
            

            struct {
                const char *name;
                int value;
            } flag_map[] = {
                {"syn", 0x02},
                {"ack", 0x10},
                {"fin", 0x01},
                {"rst", 0x04},
                {"psh", 0x08},
                {"urg", 0x20},
                {"ece", 0x40},
                {"cwr", 0x80}
            };
            
            char *flag_str = argv[i + 1];
            config->tcp_flags = 0;
            

            char *token;
            char *str_copy = strdup(flag_str); 
            if (!str_copy) {
                fprintf(stderr, "Error: Memory allocation failed\n");
                return -1;
            }
            
            token = strtok(str_copy, ",");
            while (token != NULL) {

                while (*token == ' ') token++;
                char *end = token + strlen(token) - 1;
                while (end > token && *end == ' ') end--;
                *(end + 1) = '\0';
                

                char lower_token[32];
                strncpy(lower_token, token, sizeof(lower_token));
                lower_token[sizeof(lower_token) - 1] = '\0';
                for (int j = 0; lower_token[j]; j++) {
                    lower_token[j] = tolower(lower_token[j]);
                }
                

                int found = 0;
                for (size_t j = 0; j < sizeof(flag_map)/sizeof(flag_map[0]); j++) {
                    if (strcmp(lower_token, flag_map[j].name) == 0) {
                        config->tcp_flags |= flag_map[j].value;
                        found = 1;
                        break;
                    }
                }
                
                if (!found) {
                    fprintf(stderr, "Error: Unknown flag: %s\n", token);
                    free(str_copy);
                    return -1;
                }
                
                token = strtok(NULL, ",");
            }
            
            free(str_copy);
            printf("Flags set: 0x%02x\n", config->tcp_flags);
            i++; 
        }
        else if (strcmp(argv[i], USER_ARP) == 0) {
            config->arp_scan = 1;
            printf("ARP scan requested\n");

        }
        else if (strcmp(argv[i], USER_SPOOFIP) == 0) {

            if (i + 1 >= argc) {
                fprintf(stderr, "Error: %s requires a source IP argument\n", USER_SPOOFIP);
                return -1;
            }
            
            if (strlen(argv[i + 1]) > 15) {
                fprintf(stderr, "Error: Invalid spoof IP address format\n");
                return -1;
            } 
            config->ip_true = 1;
            config->ip_src = argv[i + 1];
	    inet_pton(AF_INET, argv[i + 1], &config->ip_src_bytes);
            i++; 
        } 
	else if (strcmp(argv[i], USER_SPOOFMAC) == 0) {

            if (i + 1 >= argc) {
                fprintf(stderr, "Error: %s requires a source MAC argument in the format of ff:ff:ff:ff:ff:ff\n", USER_SPOOFMAC);
                return -1;
            }
            if (sscanf(argv[i + 1], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &config->mac_src[0], &config->mac_src[1], &config->mac_src[2], &config->mac_src[3], &config->mac_src[4], &config->mac_src[5]) != 6) {
		fprintf(stderr, "Invalid spoof mac address format\n");
            }
	    config->mac_true = 1;
            i++; 
        }
        else {
            fprintf(stderr, "Error: Unknown argument: %s\n", argv[i]);
            fprintf(stderr, "Valid arguments: %s, %s, %s, %s, %s, %s, %s\n",
                   USER_PORTS, USER_IP, USER_PORTLIST, 
                   USER_FLAGS, USER_ARP, USER_SPOOFIP, USER_SPOOFMAC);
            return -1;
        }
    }
    return 0; 
}



void *ll_scan(void *ll_args) {
    ll_scan_args *ll_scan = (ll_scan_args *)ll_args;
    ssize_t sent_bytes_pkt = 0;
    char port_buff[5];
    uint16_t d_port;
    ssize_t pkt_size = sizeof(struct ll_packet);
    struct ll_packet pkt_ll;
    struct sockaddr_ll src_addr = {0};
    socklen_t src_addr_len = sizeof(src_addr); 
    int num_ports;
		if (ll_scan->config->end_port != 0) {
			num_ports = ll_scan->config->end_port - ll_scan->config->start_port;
		} else {
			num_ports = 0;
		}
	

		if (ll_scan->config->pfile_true == 1) {
			for (int i = 0;i < ll_scan->config->pfile_portnum;i++) {					
				d_port = ll_scan->config->pfile_ports[i];
				build_pkt_ll(ll_scan->if_config, &pkt_ll, ll_scan->config->ip_rcv, ll_scan->dst_mac, d_port, ll_scan->config->tcp_flags);
        	      		sleep(1);
              			sent_bytes_pkt = send_pkt(ll_scan->eth_sock, &pkt_ll, ll_scan->rcv_dev, ll_scan->rcv_dev_len, pkt_size);
			}		
		} else {
			for (int i = 0;i <= num_ports;i++) {
             			d_port = ll_scan->config->start_port + i;
              			build_pkt_ll(ll_scan->if_config, &pkt_ll, ll_scan->config->ip_rcv, ll_scan->dst_mac, d_port, ll_scan->config->tcp_flags);
              			sleep(1);
              			sent_bytes_pkt = send_pkt(ll_scan->eth_sock, &pkt_ll, ll_scan->rcv_dev, ll_scan->rcv_dev_len, pkt_size);
        		}


		}	
		

        	
	free(ll_scan->config->pfile_ports);
        free(ll_scan);
        pthread_exit(NULL);
}

void *ll_recv (void *ll_args) {
    ll_recv_args *recv_ll = (ll_recv_args *)ll_args;
    struct ll_packet pkt;
    int log_counter = 0;
    int max_wait_seconds = 60;
    time_t start_time = time(NULL);
    int num_port = 0;
    		if (recv_ll->config->pfile_true == 1) {
			num_port = recv_ll->config->pfile_portnum;
    		} else if (recv_ll->config->end_port == 0) {
			num_port = 1;
    		} else {
		    	num_port = recv_ll->config->end_port - recv_ll->config->start_port;
		}


 
    while(1) {

        if (time(NULL) - start_time >= max_wait_seconds) {
            printf("Timeout after %d seconds\n", max_wait_seconds);
            break;
        }
       	
        if (log_counter != num_port + 1) {
       		ssize_t recv_size_pkt = recvfrom(recv_ll->eth_sock, &pkt, sizeof(struct ll_packet), 0, (struct sockaddr *)recv_ll->rcv_dev, &recv_ll->rcv_dev_len);
           
            if (recv_size_pkt == -1) {
                printf("rcv bytes pkt%d %s\n", errno, strerror(errno));
                break;
            }
            if (recv_size_pkt == 0) {
                printf("no data recv\n");
		continue;
            }
            if (recv_size_pkt > 0) {
                if (pkt.eth_hdr.h_proto != htons(ETH_P_ARP)) {
                    if (memcmp(recv_ll->dst_mac, &pkt.eth_hdr.h_source, ETH_ALEN) == 0) {
                        log_counter += 1;
                        if ((log_port_csv(recv_ll->file_fd, &pkt, recv_size_pkt)) == -1) {
                            perror("log port ll_recv\n");
                            exit(EXIT_FAILURE);
                        }
                    }
                }
            }
        } else {
            break;
        }
    }
    close(recv_ll->eth_sock);
    free(recv_ll->rcv_dev);
    free(recv_ll);
    pthread_exit(NULL);
}


void *ip_scan(void *scan_ip_args) {
    ip_scan_args *ip_args = (ip_scan_args *)scan_ip_args;
    int num_ports;
    uint16_t d_port;
    char port_buff[5];
    ssize_t pkt_size = sizeof(struct ip_packet);
    struct ip_packet pkt_ip;
    struct sockaddr_in src_addr = {0};
    socklen_t src_addr_len = sizeof(src_addr);

		if (ip_args->config->end_port != 0) {
			num_ports = ip_args->config->end_port - ip_args->config->start_port;
		} else {
			num_ports = 0;
		}
		if (ip_args->config->pfile_true == 1) {

 			for (int i = 0;i < ip_args->config->pfile_portnum;i++) {					
				d_port = ip_args->config->pfile_ports[i];								
 				build_pkt_ip(ip_args->if_config, &pkt_ip, ip_args->config->ip_rcv, d_port, ip_args->config->tcp_flags);
     				ssize_t sent_bytes_pkt = send_pkt(ip_args->sock, &pkt_ip, ip_args->in_dev, ip_args->rcv_dev_len, pkt_size);
			}

		} else {

			for (int i = 0;i <= num_ports;i++) {
            			d_port = ip_args->config->start_port + i;
            			build_pkt_ip(ip_args->if_config, &pkt_ip, ip_args->config->ip_rcv, d_port, ip_args->config->tcp_flags);
            			ssize_t sent_bytes_pkt = send_pkt(ip_args->sock, &pkt_ip, ip_args->in_dev, ip_args->rcv_dev_len, pkt_size);
      			}

		}

      
    close(ip_args->sock); 
    free(ip_args->config->pfile_ports);
    free(ip_args->in_dev);
    free(ip_args);
    pthread_exit(NULL);
}

void *ip_recv(void *recv_ip_args) {
  ip_recv_args *ip_args = (ip_recv_args *)recv_ip_args;
  int num_port = 0;
  char plc_hold[5];
  int rcv = 0;
  struct ll_packet pkt;
  int max_wait_seconds = 60;
  time_t start_time = time(NULL);
  		if (ip_args->config->pfile_true == 1) {
			num_port = ip_args->config->pfile_portnum;
    		} else if (ip_args->config->end_port == 0) {
			num_port = 1;
		} else {
			num_port = ip_args->config->end_port - ip_args->config->start_port;
		}

  while(1) {

    	if (time(NULL) - start_time >= max_wait_seconds) {
        	printf("Timeout after %d seconds\n", max_wait_seconds);
        	break;
    	}
    
    if (rcv != num_port)  {
        ssize_t pkt_recvbytes = recvfrom(ip_args->if_sock, &pkt, sizeof(struct ll_packet), 0, 
                                        (struct sockaddr *)ip_args->if_dev, &ip_args->if_dev_len);
        if (pkt_recvbytes == -1) {
            printf("rcv bytes pkt%d %s\n", errno, strerror(errno));
            break;
            continue;
        }
        if (pkt_recvbytes == 0) {

            printf("no data rcv pkt\n");
	    continue;
        }
        if (memcmp(&ip_args->ip_recv_b, &pkt.ip_hdr.saddr, IPV4_ALEN) == 0) {
            rcv += 1;
            if (log_port_csv(ip_args->file_fd, &pkt, pkt_recvbytes) == -1) {
                perror("log error\n");
                close(ip_args->if_sock);
                free(ip_args);
                exit(EXIT_FAILURE);
            }
        }
    } else {

        break;
    }
  }
  
  printf("CLEANUP, WRITTEN TO FILE\n");
  close(ip_args->if_sock);
  free(ip_args);
  pthread_exit(NULL);
}

void thread_handle_ll(ll_recv_args *recv_ll_args, ll_scan_args *scan_ll_args) {
      pthread_t ll_scan_thread;
      pthread_t ll_recv_thread;

      
            if (pthread_create(&ll_scan_thread, 0, ll_scan, scan_ll_args) != 0) {
                printf("pthread create ll_scan_thread %d %s", errno, strerror(errno));
                exit(EXIT_FAILURE);
            }
            if (pthread_create(&ll_recv_thread, 0, ll_recv, recv_ll_args) != 0) {
                printf("pthread create ll_recv_thread %d %s", errno, strerror(errno));
                exit(EXIT_FAILURE);
            }
            if (pthread_join(ll_recv_thread, NULL) == 0) {
                printf("scan complete LL\n");
                close(recv_ll_args->eth_sock);
                close(recv_ll_args->file_fd);
                free(recv_ll_args->rcv_dev);
                free(scan_ll_args->rcv_dev);
                free(scan_ll_args);
                free(recv_ll_args);
		exit(EXIT_SUCCESS);
            }
}
          
void thread_handle_ip(ip_recv_args *args_ip_recv, ip_scan_args *args_ip_scan) {
      pthread_t ip_scan_thread;
      pthread_t ip_recv_thread;

      
 	if (pthread_create(&ip_scan_thread, 0, ip_scan, args_ip_scan) != 0) {
                  printf("pthread create ip_scan_thread %d %s", errno, strerror(errno));
                  exit(EXIT_FAILURE);
   	}
  	if (pthread_create(&ip_recv_thread, 0, ip_recv, args_ip_recv) != 0) {
                  printf("pthread create ip_recv_thread %d %s", errno, strerror(errno));
                  exit(EXIT_FAILURE);
    	}
      	if (pthread_join(ip_recv_thread, NULL) == 0) {
                  printf("scan complete IP\n");
                  close(args_ip_recv->if_sock);
                  close(args_ip_recv->file_fd);
                  close(args_ip_scan->sock);
                  free(args_ip_scan->in_dev);
                  free(args_ip_scan);
                  free(args_ip_recv);
                  exit(EXIT_SUCCESS);
     	} 

}

int data_mgmt_ll(int recv_sock, int scan_sock,struct ifconfig *if_config, struct user_def_values *config, void *rcv_dev, socklen_t rcv_dev_len, uint32_t ip_recv_b, int file_fd) {

  unsigned char dst_mac[ETH_ALEN];  
  struct arp_req arp_frame; 
      ARP_CONSTRUCT(if_config, ip_recv_b, &arp_frame);
          if ((GET_ETH(&arp_frame, if_config, dst_mac)) == -1) {
              perror("error in getting mac\n");
              exit(EXIT_FAILURE);
          }
	if (config->mac_true == 1) {
		memcpy(&if_config->mac, &config->mac_src, ETH_ALEN);
	}
	if (config->ip_true == 1) {
		inet_pton(AF_INET, config->ip_src, &if_config->ipv4_addr);
	}

  
  ll_recv_args *recv_ll_args;
      recv_ll_args = malloc(sizeof(ll_recv_args)); 
          if (recv_ll_args == NULL) {
               perror("malloc LL recv args");
               exit(EXIT_FAILURE);
          }
	

  recv_ll_args->if_config = if_config;
  recv_ll_args->config = config;
  recv_ll_args->eth_sock = recv_sock;
  recv_ll_args->rcv_dev = rcv_dev;
  recv_ll_args->rcv_dev_len = rcv_dev_len;
  recv_ll_args->file_fd = file_fd;
  recv_ll_args->ip_recv_b = ip_recv_b;
  memcpy(recv_ll_args->dst_mac, dst_mac, ETH_ALEN);
         

  ll_scan_args *scan_ll_args;
      scan_ll_args = malloc(sizeof(ll_recv_args));
           if (scan_ll_args == NULL) {
               perror("malloc LL scan args");
               exit(EXIT_FAILURE);
           }


  scan_ll_args->if_config = if_config;
  scan_ll_args->config = config;
  scan_ll_args->eth_sock = scan_sock;
  scan_ll_args->rcv_dev = rcv_dev;
  scan_ll_args->rcv_dev_len = rcv_dev_len;
  scan_ll_args->ip_recv_b = ip_recv_b;
  memcpy(scan_ll_args->dst_mac, dst_mac, ETH_ALEN);
        
  thread_handle_ll(recv_ll_args, scan_ll_args);
}

int data_mgmt_ip(int ip_sock, struct ifconfig *if_config, struct user_def_values *config, void *in_dev, socklen_t rcv_dev_len, uint32_t ip_recv_b, int file_fd, int if_sock, void *if_dev, socklen_t if_dev_len) {


  ip_scan_args *args_ip_scan = malloc(sizeof(ip_scan_args));
        if (args_ip_scan == NULL) {
            perror("malloc IP scan args\n");
            exit(EXIT_FAILURE);
        }

	if (config->ip_true == 1) {
		inet_pton(AF_INET, config->ip_src, &if_config->ipv4_addr);
	}

	
  args_ip_scan->sock = ip_sock;
  args_ip_scan->if_config = if_config;
  args_ip_scan->config = config;
  args_ip_scan->in_dev = in_dev;
  args_ip_scan->rcv_dev_len = rcv_dev_len;
  args_ip_scan->ip_recv_b = ip_recv_b;
   

          

  ip_recv_args *args_ip_recv = malloc(sizeof(ip_recv_args));
        if (args_ip_recv == NULL) {
            perror("malloc IP recv args\n");
            exit(EXIT_FAILURE);
        }


  args_ip_recv->if_sock = if_sock;
  args_ip_recv->config = config;
  args_ip_recv->if_config = if_config;
  args_ip_recv->file_fd = file_fd;
  args_ip_recv->if_dev = if_dev;
  args_ip_recv->if_dev_len = if_dev_len;
  args_ip_recv->ip_recv_b = htonl(ip_recv_b);

          
   
  thread_handle_ip(args_ip_recv, args_ip_scan);


}


int main(int argc, char *argv[]) {
  struct user_def_values config;
  int arp_scan = 0;
  int recv_c = 0;
  struct ethhdr eth_arp_hdr;
  struct arp_rep arp_reply_frame;
  unsigned char brd_mac[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  srand(time(NULL));
  if ((arg_handle(argc, argv, &config)) == 0) {
          
          arp_scan = config.arp_scan;
          uint32_t ip_recv_b;
               if (inet_pton(AF_INET, config.ip_rcv, &ip_recv_b) == -1) {
                printf("not valid IP %d %s\n", errno, strerror(errno));
                exit(EXIT_FAILURE);
               }
          ip_recv_b = htonl(ip_recv_b);
      
          int file_fd = create_file();
              if (file_fd == -1) {
                perror("ERROR IN FILE CREATION\n");
              }
      
      struct ifconfig if_config;
      memset(&if_config, 0, sizeof(struct ifconfig));
          if ((NETLINK_HANDLE(RTM_GETROUTE, &if_config)) == -1) {
              perror("netlink handle GETROUTE err\n");
              exit(EXIT_FAILURE);
          }
      
          if ((NETLINK_HANDLE(RTM_GETLINK, &if_config)) == -1) {
              perror("netlink handle second call err\n");
              exit(EXIT_FAILURE);         
          } 
     	  
     
        if (config.arp_scan == 1) { 
             struct sockaddr_ll *ll_dev;
             ll_dev = malloc(sizeof(struct sockaddr_ll));
                  if (ll_dev == NULL) {
                      perror("ll_dev malloc\n");
                      exit(EXIT_FAILURE);
                  }  
             memset(ll_dev, 0, sizeof(struct sockaddr_ll)); 
             socklen_t ll_dev_len = sizeof(*ll_dev);
             int ll_scan_sock = linklayer_sock(ll_dev, if_config.index);
                  if (ll_scan_sock == -1) {
                      printf("ETH_SOCK RETURN -1 %d %s\n", errno, strerror(errno));
                      exit(EXIT_FAILURE);
                  }

            int ll_recv_sock = linklayer_sock(ll_dev, if_config.index);
                  if (ll_recv_sock == -1) {
                      printf("LL_SOCK RETURN -1 %d %s\n", errno, strerror(errno));
                      exit(EXIT_FAILURE);
                  }
             data_mgmt_ll(ll_scan_sock, ll_recv_sock,&if_config, &config, ll_dev, ll_dev_len, ip_recv_b, file_fd); 
        } else {
            struct sockaddr_ll if_dev = {0};
            socklen_t if_dev_len = sizeof(if_dev);
            int if_sock = linklayer_sock(&if_dev, if_config.index);
                 if (if_sock == -1) {
                      printf("IF_SOCK RETURN -1 %d %s\n", errno, strerror(errno));
                      exit(EXIT_FAILURE);               
                 }
            struct sockaddr_in *in_dev = malloc(sizeof(struct sockaddr_in));
                 if (in_dev == NULL) {
                      perror("malloc sockaddr_in in_dev\n");
                      exit(EXIT_FAILURE);
                 }                 
            socklen_t in_dev_len = sizeof(*in_dev);
            int ip_sock = iplayer_sock(in_dev, ip_recv_b);     
                 if (ip_sock == -1) {
                     printf("IP_SOCK RETURN -1 %d %s\n", errno, strerror(errno));
                     exit(EXIT_FAILURE);
                 }           
            data_mgmt_ip(ip_sock, &if_config, &config, in_dev, in_dev_len, ip_recv_b, file_fd, if_sock, &in_dev, in_dev_len);
    }
  }                        
}
