#include "structdefs.h"
#include "headers.h"



static inline bool if_def_route(const struct rtmsg *rtm)
{
    if (!rtm)
        return false;

    if (rtm->rtm_protocol != RTPROT_BOOT &&
    rtm->rtm_protocol != RTPROT_DHCP &&
    rtm->rtm_protocol != RTPROT_KERNEL)
    	return false;


    if (rtm->rtm_family != AF_INET)
        return false;

    if (rtm->rtm_dst_len != 0)
        return false;

    if (rtm->rtm_table != RT_TABLE_MAIN)
        return false;

    if (rtm->rtm_type != RTN_UNICAST)
        return false;

    return true;
}





int NETLINK_NLMSG_RD(struct nl_data *nldata, struct ifconfig *if_config, ssize_t rcv_byte) {
	int route = 0;
			
  for(struct nlmsghdr *nh_r = (struct nlmsghdr *)nldata->nl_rcv; NLMSG_OK(nh_r, rcv_byte); nh_r = NLMSG_NEXT(nh_r, rcv_byte)) {

    if (nh_r->nlmsg_seq == nh_r->nlmsg_seq) {
	
      switch(nh_r->nlmsg_type) {

        case RTM_NEWROUTE:
            struct rtmsg *rtm = (struct rtmsg *)NLMSG_DATA(nh_r);    
            int rtm_attr_size = RTM_PAYLOAD(nh_r);
	    	if ((if_def_route(rtm)) == true) { 
		if (route == 0) {   	    
              	
		for (struct rtattr *rta = (struct rtattr *)RTM_RTA(rtm); RTA_OK(rta, rtm_attr_size);rta = RTA_NEXT(rta, rtm_attr_size)) { 
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
		    	route = 1;
                        break;
                            } 
                          }
	    
	                                 
            break; //case NEWROUTE end here
		}
	}
        case RTM_NEWLINK:
          int ifi_flags = IFF_BROADCAST | IFF_UP | IFF_RUNNING | IFF_MULTICAST;
          struct ifinfomsg *ifi = (struct ifinfomsg *)NLMSG_DATA(nh_r);
          int ifi_attr_size = IFLA_PAYLOAD(nh_r);
            if (ifi->ifi_flags & ifi_flags) {
              for (struct rtattr *rta = (struct rtattr *)IFLA_RTA(ifi); RTA_OK(rta, ifi_attr_size); rta = RTA_NEXT(rta, ifi_attr_size)) {
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
		    	case IFLA_OPERSTATE: 
				data_ifl = RTA_DATA(rta);
				int oper = *(int *)data_ifl;	
					if (oper != 6) {
						continue;
					} else {
						break;
					}	
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

