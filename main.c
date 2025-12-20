#define _GNU_SOURCE
#include "include/headers.h"
#include "include/structdefs.h"
#include "include/netlink_handle.h"
#include "include/packetdefs.h"
#include "include/ll_func.h"
#include "include/ip_func.h"
#include "include/packet_func.h"
#include "include/log_func.h"
#include "include/sock_func.h"
#include "include/ioctl_func.h"
#include "include/user_func.h"
#include "include/thread_func.h"







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
