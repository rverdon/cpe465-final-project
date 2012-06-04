/**
 * DF packet
 *
 */

#define MAX_FILENAME_SIZE 200
#define MAX_INDICIES 200
#define MAX_DATA_SIZE 1024

class df_packet {
    public:
    uint16_t version;
    uint16_t type;
    uint32_t chunk_size;
    uint32_t num_chunks;
    uint16_t filename_size;
    unsigned char filename[MAX_FILENAME_SIZE];
    uint32_t degree;
    uint32_t indicies[MAX_INDICIES];
    unsigned char data[MAX_DATA_SIZE];

    df_packet()
    {
       version = 1;
    }

    int write_packet(unsigned char* buffer)
    {
       unsigned char* ptr = buffer;
       uint16_t tmp_short = 0;
       uint32_t tmp_int = 0;

       tmp_short = htons(version);
       memcpy(ptr, &tmp_short, 2);
       ptr+=2;

       tmp_short = htons(type);
       memcpy(ptr, &tmp_short, 2);
       ptr+=2;

       tmp_int = htonl(chunk_size);
       memcpy(ptr, &tmp_int, 4);
       ptr+=4;

       tmp_int = htonl(num_chunks);
       memcpy(ptr, &tmp_int, 4);
       ptr+=4;

       tmp_short = htons(filename_size);
       memcpy(ptr, &tmp_short, 2);
       ptr+=2;

       memcpy(ptr, &filename, filename_size);
       ptr+=filename_size;

       tmp_int = htonl(degree);
       memcpy(ptr, &tmp_int, 4);
       ptr+=4;
       
       for (unsigned int i = 0; i < degree; i++)
       {
          tmp_int = htonl(indicies[i]);
       	  memcpy(ptr, &tmp_int, 4);
          ptr+=4;
       }

       memcpy(ptr, &data, chunk_size);
       ptr+=chunk_size;

       return (int)(ptr - buffer);
    }

    void parse_packet(unsigned char* buffer)
    {
       unsigned char* ptr = buffer;
       uint16_t tmp_short = 0;
       uint32_t tmp_int = 0;

       memcpy(ptr, &tmp_short, 2);
       version = ntohs(tmp_short);
       ptr+=2;

       memcpy(ptr, &tmp_short, 2);
       type = ntohs(tmp_short);
       ptr+=2;

       memcpy(ptr, &tmp_int, 4);
       chunk_size = ntohl(tmp_int);
       ptr+=4;

       memcpy(ptr, &tmp_int, 4);
       num_chunks = ntohl(tmp_int);
       ptr+=4;

       memcpy(ptr, &tmp_short, 2);
       filename_size = ntohs(tmp_short);
       ptr+=2;

       memcpy(ptr, &filename, filename_size);
       ptr+=filename_size;

       memcpy(ptr, &tmp_int, 4);
       degree = ntohl(tmp_int);
       ptr+=4;
       
       for (unsigned int i = 0; i < degree; i++)
       {
          tmp_int = htonl(indicies[i]);
       	  memcpy(ptr, &tmp_int, 4);
          indicies[i] = ntohl(tmp_int);
          ptr+=4;
       }

       memcpy(ptr, &data, chunk_size);
       ptr+=chunk_size;
    }   
};
