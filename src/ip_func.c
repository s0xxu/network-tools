#include "headers.h"
#include "structdefs.h"
#include "packet_func.h"
#include "log_func.h"
#include "thread_func.h"

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
    pthread_exit(NULL);
}

void *ip_recv(void *recv_ip_args) {
  ip_recv_args *ip_args = (ip_recv_args *)recv_ip_args;
  int num_port = 0;
  char plc_hold[5];
  int log_counter = 0;
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
    if (log_counter != num_port + 1)  {
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
            log_counter += 1;
            if (log_port_csv(ip_args->file_fd, &pkt, pkt_recvbytes) == -1) {
                perror("log error\n");
  		pthread_exit(NULL);
            }
        }
    } else {

        break;
    }
  }
  pthread_exit(NULL);
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

