#ifndef IOCTL_FUNC_H
#define IOCTL_FUNC_H 

#include "headers.h"
#include "structdefs.h"

struct ifreq ifconf_name(struct ifreq ifr_conf, struct ifreq ifr_list);
int check_if_flags(struct ifreq ifr_conf);
int if_dev(struct ifconfig *if_config);


#endif
