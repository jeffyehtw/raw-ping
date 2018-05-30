#ifndef _NETWORK_H
#define _NETWORK_H

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

void set_ip_ver(struct ip *, int);

int get_ip_ver(struct ip *);

void set_ip_hlen(struct ip *, int);

int get_ip_hlen(struct ip *);

void set_ip_dscp(struct ip *, int);

int get_ip_dscp(struct ip *);

void set_ip_len(struct ip *, int);

int get_ip_len(struct ip *);

void set_ip_id(struct ip *, int);

int get_ip_id(struct ip *);

void set_ip_frag_off(struct ip *);

int get_ip_frag_off(struct ip *);

void set_ip_ttl(struct ip *, int);

int get_ip_ttl(struct ip *);

void set_ip_proto(struct ip *, int);

int get_ip_proto(struct ip *);

void set_ip_check(struct ip *);

int get_ip_check(struct ip *);

void set_ip_src_addr(struct ip *, char *);

void get_ip_src_addr(struct ip *, char *);

void set_ip_dst_addr(struct ip *, char *);

void get_ip_dst_addr(struct ip *, char *);

void set_icmp_type(struct icmp *, int);

int get_icmp_type(struct icmp *);

void set_icmp_code(struct icmp *, int);

int get_icmp_code(struct icmp *);

void set_icmp_id(struct icmp *, int);

int get_icmp_id(struct icmp *);

void set_icmp_seq(struct icmp *, int);

int get_icmp_seq(struct icmp *);

void set_icmp_sum(struct icmp *, int);

#endif
