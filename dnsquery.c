// dnsquery  by sincoder
// email:admin@sincoder.com
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netdb.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <resolv.h>
#include <time.h>

#pragma pack(push,1)
/* DNS header definition */
struct dnshdr
{
    unsigned short id;
    unsigned short flags;
    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;
};

/* DNS query structure */
struct dnsquery
{
    char *qname;
    unsigned short qtype;
    unsigned short qclass;
};

/* DNS answer structure */
struct dnsanswer
{
    char *name;
    char atype[2];
    char aclass[2];
    char ttl[4];
    char RdataLen[2];
    char *Rdata;
};

#pragma pack(pop)

int g_raw_socket = 0;
int g_scr_ip = 0;
int g_dns_ip = 0;
int g_send_interval = 0;
int g_query_count = 0;
/**
 * Calculates a checksum for a given header
 */
unsigned short csum(unsigned short *buf, int nwords)
{
    unsigned long sum;
    for (sum = 0; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return ~sum;
}

/**
 * Builds an UDP/IP datagram
 */
int build_udp_ip_datagram(char *datagram, unsigned int payload_size, uint32_t src_ip, uint32_t dst_ip, u_int16_t port)
{
    struct ip *ip_hdr = (struct ip *) datagram;
    struct udphdr *udp_hdr = (struct udphdr *) (datagram + sizeof (struct ip));

    ip_hdr->ip_hl = 5; //header length
    ip_hdr->ip_v = 4; //version
    ip_hdr->ip_tos = 0; //tos
    ip_hdr->ip_len = sizeof(struct ip) + sizeof(struct udphdr) + payload_size;  //length
    ip_hdr->ip_id = 0; //id
    ip_hdr->ip_off = 0; //fragment offset
    ip_hdr->ip_ttl = 255; //ttl
    ip_hdr->ip_p = 17; //protocol
    ip_hdr->ip_sum = 0; //temp checksum
    ip_hdr->ip_src.s_addr = src_ip; //src ip - spoofed
    ip_hdr->ip_dst.s_addr = dst_ip; //dst ip

    udp_hdr->source = port; //src port - spoofed
    udp_hdr->dest = htons(53); //dst port
    udp_hdr->len = htons(sizeof(struct udphdr) + payload_size); //length
    udp_hdr->check = 0; //checksum - disabled

    ip_hdr->ip_sum = csum((unsigned short *) datagram, ip_hdr->ip_len >> 1); //real checksum

    return ip_hdr->ip_len >> 1;
}

void Sleep(uint32_t msec)
{
    struct timespec slptm;
    slptm.tv_sec = msec / 1000;
    slptm.tv_nsec = 1000 * 1000 * (msec - (msec / 1000) * 1000);      //1000 ns = 1 us
    if (nanosleep(&slptm, NULL) != -1)
    {

    }
    else
    {
        fprintf(stderr,"%s : %u", "nanosleep failed !!\n", msec);
    }
}


static void show_usage_msg()
{
    printf("copyright 2013 sincoder\n");
    printf("Usage:dnsquery [srcip] [domain] [dns server] [query count] [send interval]\n"
           "example: dnsquery 192.168.11.1 www.baidu.com 8.8.8.8 2 1000\n");
}

int create_raw_socket()
{
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    int one = 1;
    const int *val = &one;

    if (sock < 0)
    {
        fprintf(stderr, "Error creating socket \n");
        return -1;
    }

    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
    {
        fprintf(stderr, "Error at setsockopt() \n");
        close(sock);
        return -1;
    }
    return sock;
}

/*
in : www.sincoder.com\x0
out: \x3www\x8sincoder\x3com\x0
*/
int  make_dns_query_domain(char *domain)
{
    char out[256];
    char *p = domain;
    char *pout = &out[0];
    while (*p)
    {
        int size = 0;
        char *pdomain = p;
        while (*pdomain && *pdomain != '.')
        {
            size++;
            pdomain++;
        }
        pout[0] = size;
        pout ++;
        strncpy(pout, p, size);
        pout += size;
        p = pdomain;
        if ('.' == *p)
        {
            p++;
        }
    }
    *(pout) = 0;
    memcpy(domain, &out[0], pout - &out[0] + 1);
    return pout - &out[0] + 1;
}

uint16_t  random16()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint16_t)(tv.tv_sec * tv.tv_usec);
}

unsigned short query_id = 0x0;
void send_dns_query_packet(char *domain)
{
    struct sockaddr_in to_addr;
    int bytes_sent;
    int len = 0;
    char packet[1500];
    char query_domain[256];
    struct dnshdr *dns_header = (struct dnshdr *)(&packet[0] + sizeof(struct ip) + sizeof(struct udphdr)) ;

    strncpy(query_domain, domain, 256);
    dns_header->id = query_id ++;
    dns_header->flags = 0x0001;
    dns_header->qdcount = 0x0100;
    dns_header->ancount = 0x0000;
    dns_header->nscount = 0x0000;
    dns_header->arcount = 0x0000;

    len = make_dns_query_domain(&query_domain[0]);

    strcpy((char *)(dns_header + 1), query_domain);

    *(int *)((char *)(dns_header + 1) + len) = 0x01000100;

    len = len + sizeof(struct dnshdr) + 4;

    //printf("payload size %d\n", len);

    build_udp_ip_datagram(packet, len, g_scr_ip, g_dns_ip, random16());

    to_addr.sin_family = AF_INET;
    to_addr.sin_port = htons(53);
    to_addr.sin_addr.s_addr = g_dns_ip;

    len += (sizeof(struct ip) + sizeof(struct udphdr));

    bytes_sent = sendto(g_raw_socket, packet, len, 0, (struct sockaddr *)&to_addr, sizeof(to_addr));
    if (bytes_sent < 0)
    {
        fprintf(stderr, "Error sending data \n");
    }
}


int main(int argc, char **argv)
{
    int idx = 0;
    if (argc < 5)
    {
        show_usage_msg();
        return -1;
    }
    g_raw_socket = create_raw_socket();
    if (-1 == g_raw_socket)
    {
        fprintf(stderr, "create raw socket failed !	\n");
        return -2;
    }
    g_dns_ip = inet_addr(argv[3]);
    if (0 == g_dns_ip)
    {
        fprintf(stderr, "dns server ip error !!\n");
        close(g_raw_socket);
        return -3;
    }
    g_scr_ip = inet_addr(argv[1]);
    if (0 == g_scr_ip)
    {
        fprintf(stderr, "src ip error !!\n");
        close(g_raw_socket);
        return -4;
    }
    g_send_interval = atoi(argv[5]);

    if (g_send_interval > 1000)
    {
        fprintf(stderr, "send interval is %d maybe too long \n", g_send_interval );
    }
    g_query_count = atoi(argv[4]);
    if (0 == g_query_count)
    {
        fprintf(stderr, "query count is 0 ,I will set it to 1 ! \n");
    	g_query_count = 1;
    }
    for (idx = 0; idx < g_query_count; )
    {
        send_dns_query_packet(argv[2]);
        if(g_send_interval)
            Sleep(g_send_interval);
        printf("\rsend %d packets",++idx);
    }
    printf("\n");
    close(g_raw_socket);
    return 0;
}
