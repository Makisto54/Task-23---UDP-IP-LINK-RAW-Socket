#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <net/if.h>
#include <linux/ip.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <linux/udp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#define BUF_SIZE 255
#define HEADERS_SIZE 42
#define DEST_PORT 0xAABB
#define SOURCE_PORT 0xBBAA
#define CLIENT_ADDR "172.17.0.1"
#define SERVER_ADDR "172.17.0.2"

unsigned short checksum(unsigned short* buf)
{
    int csum = 0;
    int ptr_sum = 0;
    unsigned short *ptr = buf;

    for (int i = 0; i < 10; i++)
    {
        csum += *ptr;
        ptr++;
    }
    ptr_sum = csum >> 16;
    csum += ptr_sum;
    return ~csum;
}

void error_macro(const char *error)
{
    perror(error);
    exit(1);
}

int main(void)
{
    int val = 1;
    int address = 0;
    char *ptr = NULL;
    int socket_fd = 0;
    struct iphdr *ip = {0};
    struct udphdr *udp = {0};
    struct ethhdr *eth = {0};
    char buf[BUF_SIZE] = {0};
    struct sockaddr_ll client = {0};
    struct sockaddr_ll server = {0};
    socklen_t client_socket_fd_size = 0;
    char ip_address[INET_ADDRSTRLEN] = {0};
    char msg_buf[BUF_SIZE - HEADERS_SIZE] = {0};

    unsigned char dest_mac[ETH_ALEN] = {0x02, 0x42, 0xAC, 0x11, 0x00, 0x02};
    //unsigned char dest_mac[ETH_ALEN] = {0xAA, 0x42, 0x8A, 0x88, 0xDD, 0xAB};
    unsigned char source_mac[ETH_ALEN] = {0x02, 0x42, 0xF8, 0x31, 0x0D, 0xE2};

    socket_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (socket_fd == -1)
    {
        error_macro("SOCKET CREATE");
    }

    server.sll_hatype = 0;
    server.sll_pkttype = 0;
    server.sll_protocol = 0;
    server.sll_halen = ETH_ALEN;
    server.sll_family = AF_PACKET;
    server.sll_ifindex = if_nametoindex("docker0");
    for (int i = 0; i < ETH_ALEN; i++)
    {
        server.sll_addr[i] = dest_mac[i];
    }

    client_socket_fd_size = sizeof(struct sockaddr_ll);
    do
    {
        ptr = buf;
        bzero(buf, BUF_SIZE);
        bzero(ip_address, INET_ADDRSTRLEN);
        bzero(msg_buf, BUF_SIZE - HEADERS_SIZE);

        eth = (struct ethhdr*)buf;

        for (int i = 0; i < ETH_ALEN; i++)
        {
            eth->h_dest[i] = dest_mac[i];
            eth->h_source[i] = source_mac[i];
        }

        eth->h_proto = htons(ETH_P_IP);

        ptr += sizeof(struct ethhdr);

        ip = (struct iphdr*)(buf + sizeof(struct ethhdr));

        ip->id = 0;
        ip->ihl = 5;
        ip->tos = 0;
        ip->ttl = 255;
        ip->version = 4;
        ip->frag_off = 0;
        ip->protocol = IPPROTO_UDP;
        ip->tot_len = htons(BUF_SIZE - sizeof(struct ethhdr));

        int ret = inet_pton(AF_INET, CLIENT_ADDR, &address);
        if (ret == -1 || ret == 0)
        {
            error_macro("INET PTON");
        }
        ip->saddr = address;

        ret = inet_pton(AF_INET, SERVER_ADDR, &address);
        if (ret == -1 || ret == 0)
        {
            error_macro("INET PTON");
        }
        ip->daddr = address;
        ip->check = checksum((unsigned short*)buf);

        ptr += sizeof(struct iphdr);

        udp = (struct udphdr*)(buf + sizeof(struct iphdr) + sizeof(struct ethhdr));

        udp->dest = htons(DEST_PORT);
        udp->source = htons(SOURCE_PORT);
        udp->len = htons(BUF_SIZE - sizeof(struct iphdr) - sizeof(struct ethhdr));
        udp->check = 0;

        ptr += sizeof(struct udphdr);

        fgets(msg_buf, BUF_SIZE - HEADERS_SIZE, stdin);
        char *p = strchr(msg_buf, '\n');
        if (p != NULL)
        {
            msg_buf[strlen(msg_buf) - 1] = '\0';
        }
        memcpy(ptr, msg_buf, BUF_SIZE - HEADERS_SIZE);

        if (sendto(socket_fd, buf, BUF_SIZE, 0, (struct sockaddr *)&server,
            client_socket_fd_size) == -1)
        {
            error_macro("SEND ERROR");
        }

        for (;;)
        {
            if (recvfrom(socket_fd, buf, BUF_SIZE, 0, (struct sockaddr *)&client,
                &client_socket_fd_size) == -1)
            {
                error_macro("RECVFROM ERROR");
            }

            eth = (struct ethhdr*)buf;
            ip = (struct iphdr*)(buf + sizeof(struct ethhdr));
            udp = (struct udphdr*)(buf + sizeof(struct iphdr) + sizeof(struct ethhdr));

            if (NULL == inet_ntop(AF_INET, &ip->saddr, ip_address, INET_ADDRSTRLEN))
            {
                error_macro("INET NTOP");
            }

            if ((strncmp(source_mac, eth->h_dest, ETH_ALEN) == 0)
                &&(strncmp(SERVER_ADDR, ip_address, INET_ADDRSTRLEN) == 0)
                && ntohs(udp->dest) == SOURCE_PORT)
            {
                printf("Received Message - %s\n", (buf + sizeof(struct udphdr)
                    + sizeof(struct iphdr) + sizeof(struct ethhdr)));
                break;
            }
        }
    } while (strncmp((buf + sizeof(struct udphdr) + sizeof(struct iphdr)
        + sizeof(struct ethhdr)), "exit", BUF_SIZE) != 0);

    return 0;
}
