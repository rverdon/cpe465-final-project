/**
 * DF packet
 *
 */

#define MAX_FILENAME_SIZE 200
#define MAX_INDICIES 500
#define MAX_DATA_SIZE 512

class df_packet {
    public:
    uint16_t version;
    uint16_t type;
    uint32_t chunk_size;
    uint32_t num_chunks;
    uint32_t filesize;
    uint16_t filename_size;
    unsigned char filename[MAX_FILENAME_SIZE];
    uint32_t degree;
    uint32_t indicies[MAX_INDICIES];
    unsigned char data[MAX_DATA_SIZE];

    df_packet()
    {
       version = 1;
       type = 1;
       memset(filename, 0, MAX_FILENAME_SIZE);
       memset(data, 0, MAX_DATA_SIZE);
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

       tmp_int = htonl(filesize);
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

       memcpy(&tmp_short,ptr, 2);
       version = ntohs(tmp_short);
       ptr+=2;

       memcpy(&tmp_short,ptr, 2);
       type = ntohs(tmp_short);
       ptr+=2;

       memcpy(&tmp_int,ptr, 4);
       chunk_size = ntohl(tmp_int);
       ptr+=4;

       memcpy(&tmp_int,ptr, 4);
       num_chunks = ntohl(tmp_int);
       ptr+=4;

       memcpy(&tmp_int,ptr, 4);
       filesize = ntohl(tmp_int);
       ptr+=4;

       memcpy(&tmp_short,ptr, 2);
       filename_size = ntohs(tmp_short);
       ptr+=2;

       memcpy(&filename, ptr, filename_size);
       ptr+=filename_size;

       memcpy(&tmp_int, ptr, 4);
       degree = ntohl(tmp_int);
       ptr+=4;
       
       for (unsigned int i = 0; i < degree; i++)
       {
       	  memcpy(&tmp_int, ptr, 4);
          indicies[i] = ntohl(tmp_int);
          ptr+=4;
       }

       memcpy(&data,ptr, chunk_size);
       ptr+=chunk_size;
    }
 
    void xor_data_from_file(FILE* fp, uint32_t index, int size)
    {
       //printf("XOR DATA FROM FILE!\n");
       //printf("OFFSET = %d\n", index*size);
       unsigned char buffer[MAX_DATA_SIZE];
       memset(buffer, 0, MAX_DATA_SIZE);
       //MOVE the file cursor
       fseek(fp, index*size, 0);
       fread(buffer, 1, size, fp);
       xor_data_from_buffer(buffer, size);
    }

    void xor_data_from_buffer(unsigned char* buf, int size)
    {
       for(int i = 0; i < size; i++)
       {
          data[i] ^= buf[i];
       }
    }

    void debug_print()
    {
       printf("\nDebug print\n");
       printf("Version: %d\n", version);
       printf("Type: %d\n", type);
       printf("Chunk_size: %d\n", chunk_size);
       printf("Num_chunks: %d\n", num_chunks);
       printf("Filesize: %d\n", filesize);
       printf("Filename_size: %d\n", filename_size);
       printf("filename: %s\n", filename);
       printf("Degree: %d\n", degree);
       for(unsigned int i = 0; i < degree; i++)
       {
          printf("indicies[%d]: %d\n", i, indicies[i]);
       }
    }
};
