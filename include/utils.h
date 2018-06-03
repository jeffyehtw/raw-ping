#ifndef _UTILS_H
#define _UTILS_H

#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <netinet/ip_icmp.h>

#define IP_HDR_LEN 20
#define ICMP_HDR_LEN 8
#define DATA_LEN 4
#define FRAME_LEN 32

char *allocate_strmem (int);

uint8_t *allocate_ustrmem(int);

uint16_t icmp_checksum(struct icmp *, uint8_t *, int);

uint16_t checksum(uint16_t *, int);

void print_packet(const uint8_t *, int);

#endif
