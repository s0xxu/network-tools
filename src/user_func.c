#include "headers.h"
#include "structdefs.h"
#include "packetdefs.h"








int arg_handle(int argc, char *argv[], struct user_def_values *config) {

    memset(config, 0, sizeof(struct user_def_values));
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], USER_PORTS) == 0) {

            if (i + 1 >= argc) {
                fprintf(stderr, "Error: %s requires an argument (e.g., 443-448)\n", USER_PORTS);
                return -1;
            }
            if (sscanf(argv[i + 1], "%hu-%hu", &config->start_port, &config->end_port) == 2) {
                                if (config->start_port > config->end_port) {
                                        fprintf(stderr, "Error: Start port cannot be greater than end port\n");
                                        return -1;
                                }
                        i++;
                        continue;
            } else if (sscanf(argv[i + 1], "%hu", &config->start_port) == 1) {
                        config->end_port = 0;
                                if (config->start_port > 65535 || config->end_port > 65535) {
                                        fprintf(stderr, "Error: Port numbers must be between 0-65535\n");
                                        return -1;
                                }
                        i++;
            } else {
                fprintf(stderr, "Error: No argument provided\n");
            }


        }
        else if (strcmp(argv[i], USER_IP) == 0) {

            if (i + 1 >= argc) {
                fprintf(stderr, "Error: %s requires an IP address argument\n", USER_IP);
                return -1;
            }


            if (strlen(argv[i + 1]) > 17) {
                fprintf(stderr, "Error: Invalid IP address format\n");
                return -1;
            }
            config->ip_rcv = argv[i + 1];
            i++;
        }
        else if (strcmp(argv[i], USER_PORTLIST) == 0) {

            if (i + 1 >= argc) {
                fprintf(stderr, "Error: %s requires a port list argument\n", USER_PORTLIST);
                return -1;
            }

            if (strlen(argv[i + 1]) >= sizeof(config->pfile_name)) {
                fprintf(stderr, "Error: Port list too long (max %zu characters)\n",
                       sizeof(config->pfile_name) - 1);
                return -1;
            }
                config->pfile_true = 1;
                strncpy(config->pfile_name, argv[i + 1], sizeof(config->pfile_name) - 1);
                config->pfile_name[sizeof(config->pfile_name) - 1] = '\0';
                config->pfile_fd = open(config->pfile_name, O_RDONLY, 0);

                        if (config->pfile_fd == -1) {
                                printf("port file open err %d %s", errno, strerror(errno));
                                return -1;
                        }

                        char port_buff[6];
                        config->pfile_ports = malloc(4096);
                        FILE *fp = fdopen(config->pfile_fd, "r");

                                while(fgets(port_buff, sizeof(port_buff), fp)) {
                                        uint16_t port_value = (uint16_t)atoi(port_buff);
                                                if (port_value != 0) {
                                                        config->pfile_ports[config->pfile_portnum] = port_value;
                                                        config->pfile_portnum += 1;
                                                }
                                }
                                fclose(fp);
                                close(config->pfile_fd);
                        i++;
        }
        else if (strcmp(argv[i], USER_FLAGS) == 0) {

            if (i + 1 >= argc) {
                fprintf(stderr, "Error: %s requires a flag value\n", USER_FLAGS);
                return -1;
            }


            struct {
                const char *name;
              int value;
            } flag_map[] = {
                {"syn", 0x02},
                {"ack", 0x10},
                {"fin", 0x01},
                {"rst", 0x04},
                {"psh", 0x08},
                {"urg", 0x20},
                {"ece", 0x40},
                {"cwr", 0x80}
            };

            char *flag_str = argv[i + 1];
            config->tcp_flags = 0;


            char *token;
            char *str_copy = strdup(flag_str);
            if (!str_copy) {
                fprintf(stderr, "Error: Memory allocation failed\n");
                return -1;
            }

            token = strtok(str_copy, ",");
            while (token != NULL) {

                while (*token == ' ') token++;
                char *end = token + strlen(token) - 1;
                while (end > token && *end == ' ') end--;
                *(end + 1) = '\0';


                char lower_token[32];
                strncpy(lower_token, token, sizeof(lower_token));
                lower_token[sizeof(lower_token) - 1] = '\0';
                for (int j = 0; lower_token[j]; j++) {
                    lower_token[j] = tolower(lower_token[j]);
                }


                int found = 0;
                for (size_t j = 0; j < sizeof(flag_map)/sizeof(flag_map[0]); j++) {
                    if (strcmp(lower_token, flag_map[j].name) == 0) {
                        config->tcp_flags |= flag_map[j].value;
                        found = 1;
                        break;
                    }
                }

                if (!found) {
                    fprintf(stderr, "Error: Unknown flag: %s\n", token);
                    free(str_copy);
                    return -1;
                }

                token = strtok(NULL, ",");
            }

            free(str_copy);
            printf("Flags set: 0x%02x\n", config->tcp_flags);
            i++;
        }
        else if (strcmp(argv[i], USER_ARP) == 0) {
            config->arp_scan = 1;
            printf("ARP scan requested\n");

        }
        else if (strcmp(argv[i], USER_SPOOFIP) == 0) {

            if (i + 1 >= argc) {
                fprintf(stderr, "Error: %s requires a source IP argument\n", USER_SPOOFIP);
                return -1;
            }

            if (strlen(argv[i + 1]) > 15) {
                fprintf(stderr, "Error: Invalid spoof IP address format\n");
                return -1;
            }
            config->ip_true = 1;
            config->ip_src = argv[i + 1];
            inet_pton(AF_INET, argv[i + 1], &config->ip_src_bytes);
            i++;
        }
        else if (strcmp(argv[i], USER_SPOOFMAC) == 0) {

            if (i + 1 >= argc) {
                fprintf(stderr, "Error: %s requires a source MAC argument in the format of ff:ff:ff:ff:ff:ff\n", USER_SPOOFMAC);
                return -1;
            }
            if (sscanf(argv[i + 1], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &config->mac_src[0], &config->mac_src[1], &config->mac_src[2], &config->mac_src[3], &config->mac_src[4], &config->mac_src[5]) != 6) {
                fprintf(stderr, "Invalid spoof mac address format\n");
            }
            config->mac_true = 1;
            i++;
        }
        else {
            fprintf(stderr, "Error: Unknown argument: %s\n", argv[i]);
            fprintf(stderr, "Valid arguments: %s, %s, %s, %s, %s, %s, %s\n",
                   USER_PORTS, USER_IP, USER_PORTLIST,
                   USER_FLAGS, USER_ARP, USER_SPOOFIP, USER_SPOOFMAC);
            return -1;
        }
    }
    return 0;
}

