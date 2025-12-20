#include "headers.h"
#include "structdefs.h"


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

