#ifndef SOCK_FUNC_H
#define SOCK_FUNC_H

int linklayer_sock(struct sockaddr_ll *ll_dev, short interface);
int iplayer_sock(struct sockaddr_in *in_dev, uint32_t ip);


#endif
