#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int link_hdr_length = 0;
FILE *file = NULL;

void call_me(uint8_t *user, const struct pcap_pkthdr *pkthdr, 
              const uint8_t *packetd_ptr) 
{
    packetd_ptr += link_hdr_length;
    struct ip* ip_hdr = (struct ip *)packetd_ptr;

    char pkt_source[INET_ADDRSTRLEN];
    char pkt_destiny[INET_ADDRSTRLEN];
    char proto[10];

    int port_src;
    int port_dst;

    strcpy(pkt_source, inet_ntoa(ip_hdr->ip_src));
    strcpy(pkt_destiny, inet_ntoa(ip_hdr->ip_dst));
        
    fprintf(file, "************************************"
         "***************\n");
    switch(ip_hdr->ip_p)
    {
        case IPPROTO_TCP:
            strcpy(proto, "TCP");
            port_src = ntohs(((struct tcphdr*)packetd_ptr)->source);
            port_dst = ntohs(((struct tcphdr*)packetd_ptr)->dest);
            break;
        case IPPROTO_UDP:
            strcpy(proto, "UDP");
            port_src = ntohs(((struct udphdr*)packetd_ptr)->source);
            port_dst = ntohs(((struct udphdr*)packetd_ptr)->dest);
            break;
        case IPPROTO_ICMP:
            strcpy(proto, "ICMP");
            int icmp_type = ((struct icmphdr*)packetd_ptr)->type;
            printf("PROTO: ICMP | TYPE: %d\n", icmp_type);
            return;
        default:
            strcpy(proto, "UNKNOWN");
    }

    fprintf(file, "PROTO: %s | SRC_IP: %s | SRC_PORT: %d | DST_IP: %s | DST_PORT: %d\n", 
            proto, pkt_source, port_src, pkt_destiny, port_dst);
}

int main()
{
    //config device e limit of packets
    char *device = "wlan0";
    int packets_count = 100;

    //handling file
    file = fopen("output/logs.txt", "a");
    if(file == NULL)
    {
        printf("logs.txt could not be open\n");
        return 1;
    }
    time_t t;
    time(&t);

    char* current_date = ctime(&t);
    current_date[strcspn(current_date, "\n")] = '\0';
    
    fprintf(file, "DATE: %s\n", current_date);

    //setting a buffer for errors
    char errBuf[PCAP_ERRBUF_SIZE];

    //handle 
    pcap_t* handle = pcap_open_live(device, BUFSIZ, 1, -1, errBuf);

    if(handle == NULL)
    {
        printf("Error: %s\n", errBuf);
        exit(1);
    }

    //switch to determine the MAC length
    int link_hdr_type = pcap_datalink(handle);
    switch(link_hdr_type) 
    {
        case DLT_NULL:
            link_hdr_length = 4;
            break;
        case DLT_EN10MB:
            link_hdr_length = 14;
            break;
        default:
            link_hdr_length = 0;
    }

    //filtering
    struct bpf_program bpf;
    bpf_u_int32 netmask;
    
    char filters[128];

    printf("Set filters for the capture (or just enter to continue with no filer)\n");
    printf("Filter: ");

    if(fgets(filters, sizeof(filters), stdin) != NULL)
    {
        if(pcap_compile(handle, &bpf, filters, 0, netmask) == PCAP_ERROR)
        {
            printf("\nError at pcap_compile: %s\n", errBuf);
        }

        if (pcap_setfilter(handle, &bpf)) {
            printf("\nERR: pcap_setfilter() %s", pcap_geterr(handle));
        }

        fprintf(file, "Filters applied: %s\n", filters);
    }

    printf("\n");

    //main loop
    if (pcap_loop(handle, packets_count, call_me, (uint8_t*)NULL)) {
        printf("ERR: pcap_loop() failed!\n");
        exit(1);
    }

    fprintf(file, "\n\n\n");
    fclose(file);

    return 0;
}
