#include "headers.h"
#include "structdefs.h"


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

