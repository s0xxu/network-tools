#include "headers.h"


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

