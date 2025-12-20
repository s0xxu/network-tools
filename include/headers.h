#ifndef HEADERS_H
#define HEADERS_H
#include <stdint.h>                                                                                                                                                                           
#include <net/if.h>                                                                                                                                                                           
#include <sys/types.h>                                                                                                                                                                        
#include <sys/socket.h>                                                                                                                                                                       
#include <sys/uio.h>                                                                                                                                                                          
#include <net/if.h>                                                                                                                                                                           
#include <arpa/inet.h>                                                                                                                                                                        
#include <linux/netlink.h>                                                                                                                                                                    
#include <linux/rtnetlink.h>                                                                                                                                                                  
#include <linux/if_arp.h>                                                                                                                                                                     
#include <linux/if_ether.h>                                                                                                                                                                   
#include <linux/if_packet.h>                                                                                                                                                                  
#include <linux/ip.h>                                                                                                                                                                         
#include <linux/tcp.h>                                                                                                                                                                        
#include <linux/if_link.h>                                                                                                                                                                    
#include <linux/if_addr.h>                                                                                                                                                                    
#include <linux/sockios.h>                                                                                                                                                                    
#include <linux/types.h>  
#include <arpa/inet.h>                                                                                                                                                                        
#include <sys/socket.h>                                                                                                                                                                       
#include <linux/types.h>                                                                                                                                                                      
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
#include <stdbool.h>
#define IPV4_ALEN 4
#define ARP_PAD_FRAME_END 18
#define RCVBUF_SIZE 1024 * 1024
#define SNDBUF_SIZE 32 * 1024
#pragma GCC diagnostic ignored "-Waddress-of-packed-member"

#endif
