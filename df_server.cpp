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
    unsigned char* buffer      = NULL;
    size_t              psz    = 0;
    uint32_t            sk     = 0;
    struct sockaddr_in  addr;

    if(argc < 1)
    {
        printf("ERROR: ./df_server <file name>\n");
        exit(EXIT_FAILURE);
    }

    if ((sk = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("df_server.cpp, socket");
        exit(EXIT_FAILURE);
    }

    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = inet_addr(MULTICAST_GRP);
    addr.sin_port        = htons(MULTICAST_PORT);

    // This buffer is big enough to hold the biggest packet
    psz     = MAX_PACKET_SZ;
    buffer  = (unsigned char*)malloc(psz);

    if (sendto(sk, buffer, psz, 0, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        perror("df_server.h, join, sendto");
        exit(EXIT_FAILURE);
    }
            
    free(buffer);
    return 0;
}


/* vim: set et ai sts=2 sw=2: */
