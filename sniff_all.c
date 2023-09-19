#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include "myheader.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;
  
  printf("src MAC:");
  for(int count=0;count<6;count++)
  {
    printf("[%02x]",eth->ether_shost[count]);
  }
  printf("\n");
  printf("dst MAC:");
  for(int count=0;count<6;count++)
  {
    printf("[%02x]",eth->ether_dhost[count]);
  }

  struct ipheader * ip = (struct ipheader *)(packet + sizeof(struct ethheader));
  int ip_header_len = ip->iph_ihl *4;

  printf("\n");
  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type

    printf("src IP: %s\n", inet_ntoa(ip->iph_sourceip));   
    printf("dst IP: %s\n", inet_ntoa(ip->iph_destip));    
  }
  
    struct tcpheader * tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_len);
  printf("src PORT: %d\n", ntohs(tcp->tcp_sport));
  printf("dst PORT: %d\n", ntohs(tcp->tcp_dport));

  
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) !=0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  }

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   //Close the handle
  return 0;
}
