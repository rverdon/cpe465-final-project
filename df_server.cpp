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
#include <sys/stat.h>

#include "packet.h"

#define MAX_PACKET_SZ    1024
#define MULTICAST_PORT   60001
#define MULTICAST_GRP    "225.0.0.6"
#define CHUNK_SIZE       512

using namespace std;

void random_indicies(uint32_t* arr, uint32_t degree, int num_chunks);
bool check_uniqueness(uint32_t i, list<uint32_t> *l);


/**
 * @param argc Number of arguements.
 * @param argv Arguements on the command line.
 */
int
main(int argc, char *argv[])
{
    unsigned char*      buffer      = NULL;
    size_t              psz    = 0;
    uint32_t            sk     = 0;
    struct sockaddr_in  addr;
    int                 sz = 0;
    int                 numc = 0;
    int                 file = NULL;
    struct stat         st;

    srand((unsigned)time(0));

    if(argc < 2)
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

    //Open file
    file = open(argv[1], O_RDONLY);
    if(file == -1)
    {
       perror("df_server.h, Open failed");
       exit(EXIT_FAILURE);
    }
    //Figure out # of chunks
    fstat(file, &st);
    numc = (st.st_size / CHUNK_SIZE)+ 1;
    printf("Number of chunks is %d\n", numc);

    while(1) 
    {
       //Clear buffer
       memset(buffer, 0, psz);
       //New df_packet
       df_packet* p = new df_packet();
       //Setup meta data
       memcpy(p->filename, argv[1], strlen(argv[1])+1);
       p->filename_size = strlen(argv[1])+1;
       p->chunk_size = CHUNK_SIZE;
       p->num_chunks = numc;
       p->filesize = st.st_size;
       //Random degree(d)
       if(numc <= 50)
       {
          p->degree = (rand() % numc) + 1; // 1 <= d <= num_chunks
       }
       else 
       {
          p->degree = (rand() % 50) + 1;// LIMIT BECAUSE OF MTU!
       }
       //Choose d unique indicies
       random_indicies(p->indicies , p->degree, numc);
       //Xor data
       for (unsigned int i = 0 ; i < p->degree; i++)
       {
          p->xor_data_from_file(file, p->indicies[i], p->chunk_size);
       }
       
       p->debug_print();       
       sz = p->write_packet(buffer);
       printf("SIZE = %d\n", sz);
       //Send data
       if (sendto(sk, buffer, sz, 0, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
          perror("df_server.h, join, sendto");
          exit(EXIT_FAILURE);
       }

       delete(p);
    }

    close(file);
    free(buffer);
    return 0;
}

void 
random_indicies(uint32_t* arr, uint32_t degree, int num_chunks)
{
   list<uint32_t>* l = new list<uint32_t>();
   uint32_t num = 0;
   uint32_t i = -1;
   while(num != degree)
   {
      i = (rand() % num_chunks);
      //IF the indicies is new
      if(check_uniqueness(i, l))
      {
         l->push_back(i);
         arr[num] = i;
         num++;
      }      
   }
}

bool check_uniqueness(uint32_t i, list<uint32_t>* l)
{
   list<uint32_t>::iterator itr;
   bool not_found = true;

   for (itr=l->begin() ; itr != l->end() ; itr++)
   {
      if((uint32_t)*itr == i)
      {
         not_found = false;
      }
   }

   return not_found;
}


/* vim: set et ai sts=2 sw=2: */
