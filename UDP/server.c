#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define BUF_SIZE 255
#define ADDR_BUF_SIZE sizeof(struct in_addr)

void error_macro(const char *error)
{
    perror(error);
    exit(1);
}

int main(void)
{
    char buf[BUF_SIZE] = {0};

    int address = 0;
    int socket_fd = 0;
    socklen_t client_socket_fd_size = 0;

    struct sockaddr_in server = {0};
    struct sockaddr_in client = {0};

    socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd == -1)
    {
        error_macro("SOCKET CREATE");
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(0xAABB);
    int ret = inet_pton(AF_INET, "172.17.0.2", &address);
    if (ret == -1 || ret == 0)
    {
        error_macro("INET PTON");
    }
    server.sin_addr.s_addr = address;

    if (bind(socket_fd, (struct sockaddr *)&server, sizeof(struct sockaddr_in)) == -1)
    {
        error_macro("BIND TO SOCKET");
    }

    client_socket_fd_size = sizeof(struct sockaddr_in);
    do
    {
        if (recvfrom(socket_fd, buf, BUF_SIZE, 0, (struct sockaddr *)&client,
            &client_socket_fd_size) == -1)
        {
            error_macro("RECVFROM ERROR");
        }

        printf("Received Message - %s\n", buf);

        bzero(buf, BUF_SIZE);
        fgets(buf, BUF_SIZE, stdin);
        char *p = strchr(buf, '\n');
        if (p != NULL)
        {
            buf[strlen(buf) - 1] = '\0';
        }

        if (sendto(socket_fd, buf, BUF_SIZE, 0, (struct sockaddr *)&client,
            client_socket_fd_size) == -1)
        {
            error_macro("SENDTO ERROR");
        }

    } while (strncmp(buf, "exit", BUF_SIZE) != 0);

    close(socket_fd);

    return 0;
}
