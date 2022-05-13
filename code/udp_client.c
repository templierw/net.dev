#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#define MAXBUF 1024

int main(int argc, char *argv[])
{
    int udpSocket, addrlen;
    char buf[MAXBUF];

    struct sockaddr_in udpClient, udpServer;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s <ip address> <port>\n", *argv);
        exit(1);
    }

    /* create a socket */
    if ((udpSocket = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        fprintf(stderr, "Could not create a socket!\n");
        exit(1);
    
    } else printf("Socket created.\n");

    /* client address */
    /* use INADDR_ANY to use all local addresses */
    udpClient.sin_family = AF_INET;
    udpClient.sin_addr.s_addr = INADDR_ANY;
    udpClient.sin_port = 0;

    if ((bind(udpSocket, (struct sockaddr *)&udpClient,
              sizeof(udpClient))) == 0)
        fprintf(stderr, "Bind completed!\n");

    else {
        fprintf(stderr, "Could not bind to address!\n");
        close(udpSocket);
        exit(1);
    }

    /* set up the message to be sent to the server */
    strcpy(buf, argv[3]);
    /* server address */
    /* use the command-line arguments */
    udpServer.sin_family = AF_INET;
    udpServer.sin_addr.s_addr = inet_addr(argv[1]);
    udpServer.sin_port = htons(atoi(argv[2]));

    if ((sendto(udpSocket, buf, strlen(buf) + 1, 0,
                (struct sockaddr *)&udpServer, sizeof(udpServer))) == -1) {

        fprintf(stderr, "Could not send message!\n");
        close(udpSocket);
        return 0;
    
    } else {

        printf("Message sent.\n");
        /* message sent: look for confirmation */
        addrlen = sizeof(udpServer);
        int returnStatus = recvfrom(udpSocket, buf, MAXBUF, 0,
                                    (struct sockaddr *)&udpServer, &addrlen);
        if (returnStatus == -1)
            fprintf(stderr, "Did not receive confirmation!\n");

        else {
            buf[returnStatus] = 0;
            printf("Received: %s\n", buf);
        }
    }

    close(udpSocket);
    return 0;
}
