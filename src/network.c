#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include "utils.h"
#include "network.h"

void set_ip_ver(struct ip *self, int val) {
  self->ip_v = val;
}

int get_ip_ver(struct ip *self) {
  return self->ip_v;
}

void set_ip_hlen(struct ip *self, int val) {
  self->ip_hl = val;
}

int get_ip_hlen(struct ip *self) {
  return self->ip_hl;
}

void set_ip_dscp(struct ip *self, int val) {
  self->ip_tos = val;
}

int get_ip_dscp(struct ip *self) {
  return self->ip_tos;
}

void set_ip_len(struct ip *self, int val) {
  self->ip_len = htons(val);
}

int get_ip_len(struct ip *self) {
  return self->ip_len;
}

void set_ip_id(struct ip *self, int val) {
  self->ip_id = htons(val);
}

int get_ip_id(struct ip *self) {
  return ntohs(self->ip_id);
}

// Todo
void set_ip_frag_off(struct ip *self) {
  self->ip_off = htons(0);
}

int get_ip_frag_off(struct ip *self) {
  return ntohs(self->ip_off);
}

void set_ip_ttl(struct ip *self, int val) {
  self->ip_ttl = val;
}

int get_ip_ttl(struct ip *self) {
  return self->ip_ttl;
}

void set_ip_proto(struct ip *self, int val) {
  self->ip_p = val;
}

int get_ip_proto(struct ip *self) {
  return self->ip_p;
}

void set_ip_check(struct ip *self) {
  self->ip_sum = checksum((uint16_t *) self, self->ip_hl * 4);
}

int get_ip_checksum(struct ip *self) {
  return self->ip_sum;
}

void set_ip_src_addr(struct ip *self, char *val) {
  if (inet_pton(AF_INET, val, &(self->ip_src)) != 1) {
		perror("inet_pton()");
		exit(EXIT_FAILURE);
	}
}

void get_ip_src_addr(struct ip *self, char *val) {
  if (inet_ntop(AF_INET, &(self->ip_src), val, INET_ADDRSTRLEN)) {
		perror("inet_pton()");
		exit(EXIT_FAILURE);
	}
}

void set_ip_dst_addr(struct ip *self, char *val) {
	if (inet_pton(AF_INET, val, &(self->ip_dst)) != 1) {
		perror("inet_pton()");
		exit(EXIT_FAILURE);
	}
}

void get_ip_dst_addr(struct ip *self, char *val) {
  if (inet_ntop(AF_INET, &(self->ip_dst), val, INET_ADDRSTRLEN)) {
		perror("inet_pton()");
		exit(EXIT_FAILURE);
	}
}

void set_icmp_type(struct icmp *self, int val) {
  self->icmp_type = val;
}

int get_icmp_type(struct icmp *self) {
  return self->icmp_type;
}

void set_icmp_code(struct icmp *self, int val) {
  self->icmp_code = val;
}

int get_icmp_code(struct icmp *self) {
  return self->icmp_code;
}

void set_icmp_id(struct icmp *self, int val) {
  self->icmp_id = htons(val);
}

int get_icmp_id(struct icmp *self) {
  return self->icmp_id;
}

void set_icmp_seq(struct icmp *self, int val) {
  self->icmp_seq = htons(val);
}

int get_icmp_seq(struct icmp *self) {
  return htons(self->icmp_seq);
}

void set_icmp_sum(struct icmp *self, int val) {
  self->icmp_cksum = icmp_checksum(self, (uint8_t *) self + 8, 4);
}
