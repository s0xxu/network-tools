#include "headers.h"
#include "structdefs.h"
#include "packet_func.h"
#include "log_func.h"
#include "thread_func.h"


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
    pthread_exit(NULL);
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

