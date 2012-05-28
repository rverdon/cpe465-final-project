/**
 *  -------------------
 *    
 */

#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <string.h>
#include <ctype.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <time.h>
#include <signal.h>
#include <fcntl.h> 
#include <list>
#include <string>
#include <map>
#include <algorithm> 

#define MAX_PACKET_SZ    1024
#define MULTICAST_PORT   60001
#define MULTICAST_GRP    "225.0.0.6"

using namespace std;


/**
 * @param argc Number of arguements.
 * @param argv Arguements on the command line.
 */
int
main(int argc, char *argv[])
{
    unsigned char *packet_buffer = NULL;
    uint32_t sk                  =  0;
    uint32_t nbytes              =  0;
    uint32_t addrlen             =  0;
    uint32_t yes                 =  1;
    struct   ip_mreq mreq;
    struct   sockaddr_in addr;

    if ((sk = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("df_client.cpp, socket");
        exit(EXIT_FAILURE);
    }

    // Allow multiple sockets to use the same port
    if (setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0) {
        perror("df_client.cpp, setsockopt");
        exit(EXIT_FAILURE);
    }

    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port        = htons(MULTICAST_PORT);
    addrlen              = sizeof(addr);

    if (bind(sk, (struct sockaddr *) &addr, addrlen) < 0) {
        perror("df_client.cpp, bind");
        exit(EXIT_FAILURE);
    }

    // Use setsockopt() to join multicast group
    mreq.imr_multiaddr.s_addr = inet_addr(MULTICAST_GRP);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);

    if (setsockopt(sk, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        perror("df_client.cpp, setsockopt");
        exit(EXIT_FAILURE);
    }

    // Get a new buffer from our allocator
    packet_buffer = (unsigned char*) malloc(MAX_PACKET_SZ);

    while (1) {
        // Clear the buffer
        memset(packet_buffer, 0, MAX_PACKET_SZ);

        if ((nbytes = recvfrom(sk, packet_buffer, MAX_PACKET_SZ, 0, (struct sockaddr *) &addr, &addrlen)) < 0) {
            perror("df_client.cpp, recvfrom");
            exit(EXIT_FAILURE);
        }
        printf("Recieved %d bytes from %s\n", nbytes, inet_ntoa(addr.sin_addr));
    }

    free(packet_buffer);
    return 0;
}


/* vim: set et ai sts=2 sw=2: */
