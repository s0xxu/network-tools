#ifndef PACKET_DEFS_H
#define PACKET_DEFS_H



#define USER_PORTS "-p"
#define USER_FLAGS "-flags"
#define USER_ARP "-arp"
#define USER_IP "-ip"
#define USER_PORTLIST "-plist"
#define USER_SPOOFMAC "-spoofmac"
#define USER_SPOOFIP "-spoofip"

/* TCP Flags */
#define TCP_FIN 0x01
#define TCP_SYN 0x02  
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20
#define TCP_ECE 0x40
#define TCP_CWR 0x80

/* TCP Options */
#define TCPOPT_MIN        20
#define TCPOPT_MAX        40
#define TCPOPT_EOL        0
#define TCPOPT_NOP        1
#define TCPOPT_MSS        2
#define TCPOPT_WINDOW     3
#define TCPOPT_SACK_PERM  4
#define TCPOPT_SACK       5
#define TCPOPT_TIMESTAMP  8





/* TCP Option Builder Macros */


/* Common TCP MSS Values */
#define MSS_ETHERNET 1460
#define MSS_IPV4     536
/* MACROS */
#define ARRAY_LEN(x) (sizeof(x) / sizeof((x)[0]))

#endif
