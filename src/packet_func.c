#include "headers.h"
#include "structdefs.h"
#include "packet_func.h"

uint32_t get_tsval(void) {
    return time(NULL);
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

