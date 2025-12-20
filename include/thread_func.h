#ifndef THREAD_FUNC_H
#define THREAD_FUNC_H
#include "structdefs.h"

void thread_handle_ll(ll_recv_args *recv_ll_args, ll_scan_args *scan_ll_args);
void thread_handle_ip(ip_recv_args *args_ip_recv, ip_scan_args *args_ip_scan);


#endif
