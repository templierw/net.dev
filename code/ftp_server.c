#include <stdio.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define SERVERPORT 8888
#define MAXBUF 1024

int main() {

    int socket1, socket2,
        returnStatus, addrlen;

    struct sockaddr_in xferServer, xferClient;

    if ((socket1 = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        fprintf(stderr, "Could not create socket!\n");
        exit(1);
    }

    /* bind to a socket, use INADDR_ANY for all local addresses */
    xferServer.sin_family = AF_INET;
    xferServer.sin_addr.s_addr = INADDR_ANY;
    xferServer.sin_port = htons(SERVERPORT);

    returnStatus = bind(socket1,
                        (struct sockaddr *)&xferServer,
                        sizeof(xferServer));

    if (returnStatus == -1) {
        fprintf(stderr, "Could not bind to socket!\n");
        exit(1);
    }

    if (listen(socket1, 5) == -1) {
        fprintf(stderr, "Could not listen on socket!\n");
        exit(1);
    }

    for (;;) {
        int fd, i, readCounter, writeCounter;
        char *bufptr, buf[MAXBUF], filename[MAXBUF];
        /* wait for an incoming connection */
        addrlen = sizeof(xferClient);
        /* use accept() to handle incoming connection requests */
        /* and free up the original socket for other requests */
        if ((socket2 = accept(socket1, (struct sockaddr *)&xferClient, &addrlen)) == -1) {
            fprintf(stderr, "Could not accept connection!\n");
            exit(1);
        }

        /* get the filename from the client over the socket */
        i = 0;
        if ((readCounter = read(socket2, filename + i, MAXBUF)) > 0)
            i += readCounter;

        if (readCounter == -1) {
            fprintf(stderr, "Could not read filename from socket!\n");
            close(socket2);
            continue;
        }

        filename[i + 1] = '\0';
        printf("Reading file %s\n", filename);
        /* open the file for reading */

        if ((fd = open(filename, O_RDONLY)) == -1) {
            fprintf(stderr, "Could not open file for reading!\n");
            close(socket2);
            continue;
        }
        /* reset the read counter */
        readCounter = 0;

        /* read the file, and send it to the client in chunks of size MAXBUF */
        while ((readCounter = read(fd, buf, MAXBUF)) > 0) {
            writeCounter = 0;
            bufptr = buf;
            while (writeCounter < readCounter) {
                readCounter -= writeCounter;
                bufptr += writeCounter;
                writeCounter = write(socket2, bufptr, readCounter);
                
                if (writeCounter == -1) {
                    fprintf(stderr, "Could not write file to client!\n");
                    close(socket2);
                    continue;
                }
            }
        }
        close(fd);
        close(socket2);
    }

    close(socket1);
    return 0;
}