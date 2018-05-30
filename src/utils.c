#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include "utils.h"

char *allocate_strmem (int len) {
  void *tmp;

  if (len <= 0) {
    fprintf(stderr, "allocate_strmem()\n");
    exit(EXIT_FAILURE);
  }

  tmp = (char *) malloc(len * sizeof(char));
  if (tmp != NULL) {
    memset(tmp, 0, len * sizeof(char));
    return(tmp);
  }
  else {
    fprintf(stderr, "allocate_strmem()\n");
    exit(EXIT_FAILURE);
  }
}

uint8_t *allocate_ustrmem (int len) {
  // var
  void *tmp;

  if (len <= 0) {
    fprintf(stderr, "allocate_ustrmem()\n");
    exit(EXIT_FAILURE);
  }

  tmp = (uint8_t *) malloc(len * sizeof(uint8_t));

  if (tmp != NULL) {
    memset(tmp, 0, len * sizeof(uint8_t));
    return(tmp);
  }
  else {
    fprintf(stderr, "allocate_ustrmem()\n");
    exit(EXIT_FAILURE);
  }
}

uint16_t icmp_checksum(struct icmp *icmphdr, uint8_t *payload, int payload_len)
{
  char buf[IP_MAXPACKET];
  char *ptr;
  int check_len = 0;
  int i;

  ptr = &buf[0];

  memcpy(ptr, &icmphdr->icmp_type, sizeof(icmphdr->icmp_type));
  ptr += sizeof(icmphdr->icmp_type);
  check_len += sizeof(icmphdr->icmp_type);

  memcpy(ptr, &icmphdr->icmp_code, sizeof(icmphdr->icmp_code));
  ptr += sizeof(icmphdr->icmp_code);
  check_len += sizeof(icmphdr->icmp_code);

  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  check_len += 2;

  memcpy(ptr, &icmphdr->icmp_id, sizeof(icmphdr->icmp_id));
  ptr += sizeof(icmphdr->icmp_id);
  check_len += sizeof(icmphdr->icmp_id);

  memcpy(ptr, &icmphdr->icmp_seq, sizeof(icmphdr->icmp_seq));
  ptr += sizeof(icmphdr->icmp_seq);
  check_len += sizeof(icmphdr->icmp_seq);

  memcpy(ptr, payload, payload_len);
  ptr += payload_len;
  check_len += payload_len;

  for (i = 0; i < payload_len % 2; i++, ptr++) {
    *ptr = 0;
    ptr++;
    check_len++;
  }

  return checksum((uint16_t *) buf, check_len);
}

uint16_t checksum(uint16_t *addr, int len) {
  // variables
  int count = len;
  uint16_t res;
  register uint32_t sum = 0;

  while (count > 1) {
    sum += *(addr++);
    count -= 2;
  }

  if (count > 0) {
    sum += *(uint8_t *)addr;
  }

  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  res = ~sum;

  return res;
}
