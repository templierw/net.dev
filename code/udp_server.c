#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#define MAXBUF 1024

int main(int argc, char *argv[]) {
    int udpSocket,
        addrlen = 0;
    char buf[MAXBUF];

    struct sockaddr_in udpServer, udpClient;

    /* check for the right number of arguments */
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <port>\n", *argv);
        exit(1);
    }

    /* create a socket */
    if ((udpSocket = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        fprintf(stderr, "Could not create a socket!\n");
        exit(1);
    
    } else printf("Socket created.\n");

    /* set up the server address and port */
    /* use INADDR_ANY to bind to all local addresses */
    udpServer.sin_family = AF_INET;
    udpServer.sin_addr.s_addr = htonl(INADDR_ANY);
    /* use the port passed as argument */
    udpServer.sin_port = htons(atoi(argv[1]));

    /* bind to the socket */
    if (bind(udpSocket, 
            (struct sockaddr *)&udpServer, 
            sizeof(udpServer)
            ) == 0)

        fprintf(stderr, "Bind completed!\n");
    
    else {
        fprintf(stderr, "Could not bind to address!\n");
        close(udpSocket);
        exit(1);
    }

    while (1) {
        addrlen = sizeof(udpClient);
        if (recvfrom(udpSocket, buf, MAXBUF, 0, 
                    (struct sockaddr *)&udpClient, &addrlen) == -1)

            fprintf(stderr, "Could not receive message!\n");
        
        else {
            printf("Received: %s\n", buf);
            /* a message was received so send a confirmation */
            strcpy(buf, "OK");
            if (sendto(udpSocket, buf, strlen(buf) + 1, 0,
                                  (struct sockaddr *)&udpClient,
                                  sizeof(udpClient)) == -1)
                fprintf(stderr, "Could not send confirmation!\n");
            
            else printf("Confirmation sent.\n");
        }
    }

    close(udpSocket);
    return 0;
}
