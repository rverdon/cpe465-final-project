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
#include <queue>
#include <algorithm> 

#include "packet.h"

#define MAX_PACKET_SZ    1024
#define MULTICAST_PORT   60001
#define MULTICAST_GRP    "225.0.0.6"

using namespace std;

bool check_if_needed(uint32_t i, list<uint32_t>* l);
void add_data_to_file(FILE* file, df_packet* p);
bool check_indicies(uint32_t index, uint32_t* arr, uint32_t size);
void remove_index(uint32_t index, uint32_t* arr, uint32_t size);

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
    FILE*    file                = NULL;
    list<uint32_t>* to_do        = new list<uint32_t>();
    list<df_packet*>* packets     = new list<df_packet*>();
    queue<df_packet*>* packet_queue = new queue<df_packet*>();
    int filesize = -1;
    int done = 0;
    long num_packets_received = 0;
    long degree_one_packets = 0;
    long data_received = 0;

    setvbuf(stdout, NULL, _IONBF, 0);

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

    printf("Starting...\n");

    while (!done) {
        // Clear the buffer
        memset(packet_buffer, 0, MAX_PACKET_SZ);

        if ((nbytes = recvfrom(sk, packet_buffer, MAX_PACKET_SZ, 0, (struct sockaddr *) &addr, &addrlen)) < 0) {
            perror("df_client.cpp, recvfrom");
            exit(EXIT_FAILURE);
        }
        data_received+=nbytes;
        num_packets_received++;
        df_packet* p = new df_packet();
        p->parse_packet(packet_buffer);
        //p->debug_print();

        if(p->degree == 1)
        {
           degree_one_packets++;
        }
        
        //Check if the file is open
        if(file == NULL)
        {
           //If not create it
           file = fopen((const char*)p->filename, "w+");
           //Initialize to do index list       
           for (unsigned int i = 0; i < p->num_chunks; i++)
           {
              to_do->push_back((uint32_t)i);
           }
           filesize = p->filesize;
        }

        //Add packet to queue
        packet_queue->push(p);

        //while queue isnt empty
        while(packet_queue->size() != 0)
        {
           df_packet* packet = packet_queue->front();
           packet_queue->pop();
           //if packet degree is 1
           if(packet->degree == 1)
           {
              //IF we need the index from the packet(otherwise ignore it, extra data)
              if(check_if_needed(packet->indicies[0], to_do))
              {
                 //Add data to file
                 add_data_to_file(file, packet);
                 //remove index from to do list
                 to_do->remove(packet->indicies[0]);

                 printf("\r...%%%.1f done", (double)(packet->num_chunks- to_do->size())/packet->num_chunks * 100);
                 //If !done
                 if(to_do->size() != 0)
                 {
                    int num_packets = packets->size();
                    //Search for packets with index, xor them
                    for(int i = 0; i < num_packets;i++)
                    {
                       df_packet* temp = packets->front();
                       int flag = 0;
                       packets->pop_front();
                       
                       //IF temp contains packet index
                       if(temp->degree != 1 && check_indicies(p->indicies[0], temp->indicies, temp->degree))
                       {
                          //XOR DATA
                          temp->xor_data_from_buffer(packet->data,packet->chunk_size);
                          //DECREMENT degree
                          temp->degree--;
                          //Remove index
                          remove_index(packet->indicies[0], temp->indicies, temp->degree);
                          flag = 1;
                       }

                       //If degree becomes 1 add to queue
                       if(temp->degree == 1 && flag)
                       {
                          packet_queue->push(temp);
                       }
                       else
                       {
                          packets->push_back(temp);
                       }
                    }
                 }
                 else
                 {
                    done = 1;
                 }
                 packets->push_back(packet);
              }
           }
           else
           {
              //Find all degree 1 packets and xor data into cur packet
              int num_packets = packets->size();
              //Search for packets with index, xor them
              for(int i = 0; i < num_packets;i++)
              {
                 df_packet* temp = packets->front();
                 packets->pop_front();         
                 
                 if(temp->degree == 1)
                 {
                    //if packet contains temp's index
                    if(check_indicies(temp->indicies[0], packet->indicies, packet->degree))
                    {
                       //XOR DATA
                       packet->xor_data_from_buffer(temp->data,temp->chunk_size);
                       //DECREMENT degree
                       packet->degree--;
                       //Remove index
                       remove_index(temp->indicies[0], packet->indicies, packet->degree);
                    }
                 }
                 packets->push_back(temp);
              }

              //If degree becomes 1
              if(packet->degree == 1)
              {
                 //add to queue
                 packet_queue->push(packet);
              }
              else
              {
                 //Add to packet list
                 packets->push_back(packet);
              }
           }
         }
    }
 
    printf("\nFinished.\n");
    printf("\nResults\n");
    printf("Received %ld packets.\n", num_packets_received);
    printf("Received %ld bytes.\n", data_received);
    printf("Received %ld packets of degree 1.\n", degree_one_packets);
    printf("Received %ld packets of degree != 1.\n", num_packets_received - degree_one_packets);
    
    int fd = fileno(file);
    //Truncate file
    ftruncate(fd, filesize);
    
    fclose(file);

    delete(to_do);
    delete(packets);
    free(packet_buffer);
    return 0;
}

void add_data_to_file(FILE* file, df_packet* p)
{
   fseek(file, p->indicies[0]*p->chunk_size, 0);
   fwrite(p->data, 1, p->chunk_size, file);
   fflush(file);
}

bool check_if_needed(uint32_t i, list<uint32_t>* l)
{
   list<uint32_t>::iterator itr;
   bool not_found = true;

   for (itr=l->begin() ; itr != l->end() ; itr++)
   {
      if((uint32_t)&itr == i)
      {
         not_found = false;
      }
   }

   return not_found;
}

bool check_indicies(uint32_t index, uint32_t* arr, uint32_t size)
{
   bool found = false;
   for(unsigned int i = 0; i < size; i++)
   {
      if(arr[i] == index)
      {
         found = true;  
      }
   }
   return found;
}

void remove_index(uint32_t index, uint32_t* arr, uint32_t size)
{
   int i = 0;
   while(arr[i] != index)
   {
      i++;
   }
   
   for(unsigned int x = 0; x + i < size; x++)
   {
      arr[i+x] = arr[i+x+1];
   }
}


/* vim: set et ai sts=2 sw=2: */
