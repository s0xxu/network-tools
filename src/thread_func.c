#include "headers.h"
#include "structdefs.h"
#include "ip_func.h"
#include "ll_func.h"


void thread_handle_ll(ll_recv_args *recv_ll_args, ll_scan_args *scan_ll_args) {
      pthread_t ll_scan_thread;
      pthread_t ll_recv_thread;


            if (pthread_create(&ll_scan_thread, 0, ll_scan, scan_ll_args) != 0) {
                printf("pthread create ll_scan_thread %d %s", errno, strerror(errno));
                exit(EXIT_FAILURE);
            }
            if (pthread_create(&ll_recv_thread, 0, ll_recv, recv_ll_args) != 0) {
                printf("pthread create ll_recv_thread %d %s", errno, strerror(errno));
                exit(EXIT_FAILURE);
            }
            if (pthread_join(ll_recv_thread, NULL) != 0) {
                printf("pthread join ll_recv_thread %d %s", errno, strerror(errno));
            }
            if (pthread_join(ll_scan_thread, NULL) != 0) {
                printf("pthread join ll_scan_thread %d %s", errno, strerror(errno));
            }
                printf("LL scan complete\n");
                close(recv_ll_args->eth_sock);

                close(recv_ll_args->file_fd);
                close(recv_ll_args->eth_sock);
		free(scan_ll_args->config->pfile_ports);
		free(scan_ll_args->if_config);
                free(scan_ll_args->rcv_dev);
                free(scan_ll_args);
                free(recv_ll_args);
                return;
}

void thread_handle_ip(ip_recv_args *args_ip_recv, ip_scan_args *args_ip_scan) {
      pthread_t ip_scan_thread;
      pthread_t ip_recv_thread;


        if (pthread_create(&ip_scan_thread, 0, ip_scan, args_ip_scan) != 0) {
                  printf("pthread create ip_scan_thread %d %s", errno, strerror(errno));
                  exit(EXIT_FAILURE);
        }
        if (pthread_create(&ip_recv_thread, 0, ip_recv, args_ip_recv) != 0) {
                  printf("pthread create ip_recv_thread %d %s", errno, strerror(errno));
                  exit(EXIT_FAILURE);
        }
        if (pthread_join(ip_recv_thread, NULL) != 0) {
                  printf("pthread join ip_recv_thread %d %s", errno, strerror(errno));
		  exit(EXIT_FAILURE);
        }
	if (pthread_join(ip_scan_thread, NULL) != 0) {
                  printf("pthread join ip_scan_thread %d %s", errno, strerror(errno));
		  exit(EXIT_FAILURE);
        }
                  printf("IP scan complete\n");

		  close(args_ip_recv->if_sock);
                  close(args_ip_recv->file_fd);
		  free(args_ip_recv->if_config);
		  close(args_ip_scan->sock);
		  free(args_ip_scan->config->pfile_ports);
                  free(args_ip_scan->in_dev);
                  free(args_ip_scan);
                  free(args_ip_recv);
                  return;
}

