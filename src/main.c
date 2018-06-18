#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <argp.h>
#include <fcntl.h>
#include <unistd.h>
#include <float.h>

#include <net/if.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/ethernet.h>

#include "utils.h"
#include "network.h"

// const of args
const char *argp_program_version = "v1.0";
const char *argp_program_bug_address = "<cjyeh@cs.nctu.edu.tw>";

// documents of program
static char doc[] = "\nping";
static char args_doc[] = "";

// options of arguments
static struct argp_option options[] = {
  { "count", 'c', "N", 0, "count of probing packets" },
  { "debug", 'd', 0, 0, "show debug message" },
  { "interval", 'i', "N", 0, "seconds between periodic ICMP packets" },
  { "interface", 'I', "INTERFACE", 0, "bind to specified interface" },
  { "tos", 'Q', "N", 0, "set type of service field in IP" },
  { "size", 's', "N", 0, "set packet size" },
  { "ttl", 't', "N", 0, "set time to live field in IP" },
  { "verbose", 'v', 0, 0, "produce verbose output" },
  { "timeout", 'W', "N", 0, "timeout in second" },
  { "help", 'h', 0, 0, "show help information" },
  { 0 }
};

struct arguments {
  int count;
  int debug;
  int size;
  int tos;
  int ttl;
  int timeout;
  double interval;
  char *interface;
  char *source;
  char *destination;
};

// parse option
static error_t parse_opt(int key, char *arg, struct argp_state *state) {
  // var
  struct arguments *arguments = state->input;

  switch (key) {
    case 'c':
      arguments->count = atoi(arg);
      break;
    case 'h':
      argp_state_help(state, stdout, ARGP_HELP_STD_HELP);
      break;
    case 'i':
      arguments->interval = atof(arg);
      break;
    case 'I':
      arguments->interface = arg;
      break;
    case 'Q':
      arguments->tos = atoi(arg);
      break;
    case 's':
      arguments->size = atoi(arg);
      break;
    case 't':
      arguments->ttl = atoi(arg);
      break;
    case 'W':
      arguments->timeout = atoi(arg);
      break;
    case ARGP_KEY_ARG:
      // too many arguments
      if (state->arg_num > 1)
        argp_usage(state);
      arguments->destination = arg;
      break;
    case ARGP_KEY_END:
      // too few arguments
      if (state->arg_num < 1 || arguments->interface == NULL)
        argp_usage(state);
      break;
    default:
      return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

// argp parser
static struct argp argp = {
  options,
  parse_opt,
  args_doc,
  doc
};

int main(int argc, char **argv) {
  // variables
  int fd;
  int bytes;
  int status = 0;
  const int on = 1;

  // statistic var
  int loss = 0;
  double sum_rtt = 0;
  double min_rtt = DBL_MAX;
  double max_rtt = -DBL_MAX;

  uint8_t *request;
  uint8_t *reply;
  uint8_t *data;

  struct ifreq ifr;
  struct sockaddr_ll dev;
  struct arguments arguments;

  struct ip *send_iph;
  struct icmp *send_icmph;

  struct ip *recv_iph;
  struct icmp *recv_icmph;

  struct timeval wait;

  // set default arguments val
  arguments.count = INT_MAX;
  arguments.interval = 1;
  arguments.timeout = 2;
  arguments.interface = NULL;
  arguments.size = 56;
  arguments.ttl = 64;
  arguments.source = allocate_strmem(INET_ADDRSTRLEN);

  // parse arguments
  argp_parse(&argp, argc, argv, 0, 0, &arguments);

  request = allocate_ustrmem(IP_MAXPACKET);
  reply = allocate_ustrmem(IP_MAXPACKET);

  // clear memory of variables
  memset(&ifr, 0, sizeof(ifr));
  memset(&dev, 0, sizeof(dev));

  // set val for variables
  snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", arguments.interface);

  // find index of interface
  if ((dev.sll_ifindex = if_nametoindex(arguments.interface)) == 0) {
    perror("if_nametoindex()");
    exit(EXIT_FAILURE);
  }

  if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
    perror("socket()");
    exit(EXIT_FAILURE);
  }

  if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
    perror("socket()");
    exit(EXIT_FAILURE);
  }

  if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
    arguments.interface, strlen(arguments.interface)) < 0) {
    perror("setsockopt()");
    exit(EXIT_FAILURE);
  }

  // try to get ip addr of interface
  if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
    perror("ioctl()");
    exit(EXIT_FAILURE);
  }

  // get interface ip addr
  if (inet_ntop(AF_INET, &((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr,
    arguments.source, INET_ADDRSTRLEN) == NULL) {
    perror("inet_ntop()");
    exit(EXIT_FAILURE);
  }

  dev.sll_family = AF_INET;
  memcpy(dev.sll_addr, ifr.ifr_hwaddr.sa_data, 6);
  dev.sll_halen = 6;

  send_iph = (struct ip *) request;
  send_icmph = (struct icmp *) (request + IP_HDR_LEN);
  data = (request + IP_HDR_LEN + ICMP_HDR_LEN);
  recv_iph = (struct ip *) reply;
  recv_icmph = (struct icmp *) (reply + IP_HDR_LEN);

  // set ip header
  set_ip_ver(send_iph, 4);
  set_ip_hlen(send_iph, IP_HDR_LEN / sizeof(uint32_t));
  set_ip_dscp(send_iph, arguments.tos);
  set_ip_len(send_iph, IP_HDR_LEN + arguments.size);
  set_ip_id(send_iph, 0);
  set_ip_frag_off(send_iph);
  set_ip_ttl(send_iph, arguments.ttl);
  set_ip_proto(send_iph, IPPROTO_ICMP);
  set_ip_src_addr(send_iph, arguments.source);
  set_ip_dst_addr(send_iph, arguments.destination);
  set_ip_check(send_iph);

  // set data
  data[0] = 'N';
  data[1] = 'E';
  data[2] = 'M';
  data[3] = 'S';

  // set icmphdr header
  set_icmp_type(send_icmph, ICMP_ECHO);
  set_icmp_code(send_icmph, 0);
  set_icmp_id(send_icmph, 1000);

  // set timeout for socket
  wait.tv_sec = arguments.timeout;
  wait.tv_usec = 0;

  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
    (char *) &wait, sizeof(struct timeval));

  // show info
  printf("PING %s (%s) %d(%d) bytes of data.\n",
    arguments.destination, arguments.destination,
    arguments.size, IP_HDR_LEN + arguments.size);

  // send probing packets
  for (int i = 1; i <= arguments.count; i++) {
    // variables
    double dt = 2;
    struct timeval t1;
    struct timeval t2;

    set_icmp_seq(send_icmph, i);
    set_icmp_sum(send_icmph, arguments.size);

    if ((bytes = sendto(fd, request, IP_HDR_LEN + arguments.size, 0,
      (struct sockaddr *) &dev, sizeof(dev))) <= 0) {
      perror("sendto()");
      exit(EXIT_FAILURE);
    }

    // start timeer
    (void) gettimeofday(&t1, NULL);

    for (;;) {
      memset(reply, 0, IP_MAXPACKET * sizeof(uint8_t));

      if ((bytes = recvfrom(fd, reply, IP_MAXPACKET, 0, NULL, NULL)) < 0) {
        // status of recvfrom
        status = errno;

        if (status == EAGAIN) {
          loss++;
          break;
        }
        // Todo
        else if (status == EINTR) {
          continue;
        }
        else {
          perror("recvfrom()");
          exit(EXIT_FAILURE);
        }
      }

      if (get_ip_proto(recv_iph) == IPPROTO_ICMP
        && get_icmp_type(recv_icmph) == ICMP_ECHOREPLY
        && get_icmp_code(recv_icmph) == 0
        && get_icmp_seq(recv_icmph) == i) {

        // stop timer
        (void) gettimeofday(&t2, NULL);

        // calc rtt
        dt = (double) (t2.tv_sec - t1.tv_sec) * 1000.0
          + (double) (t2.tv_usec - t1.tv_usec) / 1000.0;

        break;
      }
    }

    if (status != EAGAIN) {
      min_rtt = dt < min_rtt ? dt : min_rtt;
      max_rtt = dt > max_rtt ? dt : max_rtt;

      printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%.3f ms\n",
      bytes, arguments.destination, get_icmp_seq(recv_icmph),
      get_ip_ttl(recv_iph), dt);

      fflush(stdout);

      sum_rtt += dt;
    }

    usleep(arguments.interval * 1000 * 1000);
  }

  // show statisics
  printf("\n--- %s ping statistics ---\n", arguments.destination);
  printf("%d packets transmitted, %d received, %d%% packet loss\n",
    arguments.count, arguments.count - loss,
    loss * 100 / arguments.count);

  if (arguments.count - loss > 0)
    printf("rtt min/avg/max = %.3f/%.3f/%.3f ms\n",
      min_rtt, sum_rtt / arguments.count, max_rtt);

  fflush(stdout);

  close(fd);

  free(arguments.source);
  free(request);
  free(reply);

  return 0;
}
