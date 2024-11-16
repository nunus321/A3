#include <stdlib.h>
#include <stdio.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>

#ifdef __APPLE__
#include "./endian.h"
#else
#include <endian.h>
#endif

#include "./networking.h"
#include "./sha256.h"

#include "networking.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

char server_ip[IP_LEN];
char server_port[PORT_LEN];
char my_ip[IP_LEN];
char my_port[PORT_LEN];

int c;

/*
 * Gets a sha256 hash of specified data, sourcedata. The hash itself is
 * placed into the given variable 'hash'. Any size can be created, but a
 * a normal size for the hash would be given by the global variable
 * 'SHA256_HASH_SIZE', that has been defined in sha256.h
 */
void get_data_sha(const char* sourcedata, hashdata_t hash, uint32_t data_size, 
    int hash_size)
{
  SHA256_CTX shactx;
  unsigned char shabuffer[hash_size];
  sha256_init(&shactx);
  sha256_update(&shactx, sourcedata, data_size);
  sha256_final(&shactx, shabuffer);

  for (int i=0; i<hash_size; i++)
  {
    hash[i] = shabuffer[i];
  }
}

/*
 * Gets a sha256 hash of specified data file, sourcefile. The hash itself is
 * placed into the given variable 'hash'. Any size can be created, but a
 * a normal size for the hash would be given by the global variable
 * 'SHA256_HASH_SIZE', that has been defined in sha256.h
 */
void get_file_sha(const char* sourcefile, hashdata_t hash, int size)
{
    int casc_file_size; 

    FILE* fp = fopen(sourcefile, "rb");
    if (fp == 0)
    {
        printf("Failed to open source: %s\n", sourcefile);
        return;
    }

    fseek(fp, 0L, SEEK_END);
    casc_file_size = ftell(fp);
    fseek(fp, 0L, SEEK_SET);

    char buffer[casc_file_size];
    fread(buffer, casc_file_size, 1, fp);
    fclose(fp);

    get_data_sha(buffer, hash, casc_file_size, size);
}

/*
 * Combine a password and salt together and hash the result to form the 
 * 'signature'. The result should be written to the 'hash' variable. Note that 
 * as handed out, this function is never called. You will need to decide where 
 * it is sensible to do so.
 */

void get_signature(char* password, char* salt, hashdata_t* hash) {
    // "Array" af karakterer til at gemme kombineret password og salt. Denne har
    // størrelse med summen af den maksimale størrelse som en password og salt må være
    char combined_input[PASSWORD_LEN + SALT_LEN];
    // Sammensætter password og salt og gemmer i combined_input
    snprintf(combined_input, sizeof(combined_input), "%s%s", password, salt);
    // Nu bruges get_data_sha til at lave en hash af password og salt.
    get_data_sha(combined_input, *hash, strlen(combined_input), SHA256_HASH_SIZE);
}

void register_user(char* username, char* password, char* salt) {
    hashdata_t hash; // En holder hvor den genererede hash skal gemmes
    get_signature(password, salt, &hash); // Kombinerer password og salt, og genererer en hash som 
                                            // gemmes i "hashdata_t hash"

    Request_t req;
    strncpy(req.header.username, username, USERNAME_LEN); // Kopierer brugernavnet til headeren
    memcpy(req.header.salted_and_hashed, hash, sizeof(hashdata_t)); // Kopierer hash ind i headeren
    req.header.length = htobe32(0); // Sætter længden til 0 og konverterer til endian(tjek edian.h)

    int sockfd;
    compsys_helper_state_t rio;
    char response_buffer[MAXBUF]; // Buffer til at modtage data

    // Opretter socket og forbinder til serveren. Tjekker om mindre end 0 så der fejl eller success
    if ((sockfd = compsys_helper_open_clientfd(server_ip, server_port)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    printf("Forbundet til serveren, sender forespørgsel...\n");
    // Sender forespørgslen til serveren
    compsys_helper_writen(sockfd, &req, sizeof(RequestHeader_t));
    printf("Forespørgsel sendt, venter på svar...\n");

    // Initialiserer I/O til at læse fra serveren
    compsys_helper_readinitb(&rio, sockfd);

 // Læser og gemmer længden af beskeden
    uint32_t length;
    compsys_helper_readnb(&rio, &length, sizeof(length));
    length = be32toh(length);  // Konvertere fra network byte order

    // Læser og gemmer status, block_id, blocks_count og block_hash, total_hash
    uint32_t status, block_id, blocks_count;
    hashdata_t block_hash, total_hash;
    
    compsys_helper_readnb(&rio, &status, sizeof(status));
    compsys_helper_readnb(&rio, &block_id, sizeof(block_id));
    compsys_helper_readnb(&rio, &blocks_count, sizeof(blocks_count));
    compsys_helper_readnb(&rio, block_hash, SHA256_HASH_SIZE);
    compsys_helper_readnb(&rio, total_hash, SHA256_HASH_SIZE);

    // Konvertere det fra network byte order
    status = be32toh(status);
    block_id = be32toh(block_id);
    blocks_count = be32toh(blocks_count);

    // Læser og gemmer reponsen fra serveren
    char message[length + 1];
    compsys_helper_readnb(&rio, message, length);

    message[length] = '\0';  // Da det er en string tilføjes "\0" i enden

    printf("Server response (Block %d/%d, Status: %d): %s\n", 
           block_id + 1, blocks_count, status, message);

    close(sockfd);
}


/*
 * Get a file from the server by sending the username and signature, along with
 * a file path. Note that this function should be able to deal with both small 
 * and large files. 
 */
void get_file(char* username, char* password, char* salt, char* to_get)
{
    // Your code here. This function has been added as a guide, but feel free 
    // to add more, or work in other parts of the code
}

int main(int argc, char **argv)
{
    // Users should call this script with a single argument describing what 
    // config to use
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <config file>\n", argv[0]);
        exit(EXIT_FAILURE);
    } 

    // Read in configuration options. Should include a client_directory, 
    // client_ip, client_port, server_ip, and server_port
    char buffer[128];
    fprintf(stderr, "Got config path at: %s\n", argv[1]);
    FILE* fp = fopen(argv[1], "r");
    while (fgets(buffer, 128, fp)) {
        if (starts_with(buffer, CLIENT_IP)) {
            memcpy(my_ip, &buffer[strlen(CLIENT_IP)], 
                strcspn(buffer, "\r\n")-strlen(CLIENT_IP));
            if (!is_valid_ip(my_ip)) {
                fprintf(stderr, ">> Invalid client IP: %s\n", my_ip);
                exit(EXIT_FAILURE);
            }
        }else if (starts_with(buffer, CLIENT_PORT)) {
            memcpy(my_port, &buffer[strlen(CLIENT_PORT)], 
                strcspn(buffer, "\r\n")-strlen(CLIENT_PORT));
            if (!is_valid_port(my_port)) {
                fprintf(stderr, ">> Invalid client port: %s\n", my_port);
                exit(EXIT_FAILURE);
            }
        }else if (starts_with(buffer, SERVER_IP)) {
            memcpy(server_ip, &buffer[strlen(SERVER_IP)], 
                strcspn(buffer, "\r\n")-strlen(SERVER_IP));
            if (!is_valid_ip(server_ip)) {
                fprintf(stderr, ">> Invalid server IP: %s\n", server_ip);
                exit(EXIT_FAILURE);
            }
        }else if (starts_with(buffer, SERVER_PORT)) {
            memcpy(server_port, &buffer[strlen(SERVER_PORT)], 
                strcspn(buffer, "\r\n")-strlen(SERVER_PORT));
            if (!is_valid_port(server_port)) {
                fprintf(stderr, ">> Invalid server port: %s\n", server_port);
                exit(EXIT_FAILURE);
            }
        }        
    }
    fclose(fp);

    fprintf(stdout, "Client at: %s:%s\n", my_ip, my_port);
    fprintf(stdout, "Server at: %s:%s\n", server_ip, server_port);

    char username[USERNAME_LEN];
    char password[PASSWORD_LEN];
    char user_salt[SALT_LEN+1];
    
    fprintf(stdout, "Enter a username to proceed: ");
    scanf("%16s", username);
    while ((c = getchar()) != '\n' && c != EOF);
    // Clean up username string as otherwise some extra chars can sneak in.
    for (int i=strlen(username); i<USERNAME_LEN; i++)
    {
        username[i] = '\0';
    }
 
    fprintf(stdout, "Enter your password to proceed: ");
    scanf("%16s", password);
    while ((c = getchar()) != '\n' && c != EOF);
    // Clean up password string as otherwise some extra chars can sneak in.
    for (int i=strlen(password); i<PASSWORD_LEN; i++)
    {
        password[i] = '\0';
    }

    // Note that a random salt should be used, but you may find it easier to
    // repeatedly test the same user credentials by using the hard coded value
    // below instead, and commenting out this randomly generating section.
    for (int i=0; i<SALT_LEN; i++)
    {
        user_salt[i] = 'a' + (random() % 26);
    }
    user_salt[SALT_LEN] = '\0';
    //strncpy(user_salt, 
    //    "0123456789012345678901234567890123456789012345678901234567890123\0", 
    //    SALT_LEN+1);

    fprintf(stdout, "Using salt: %s\n", user_salt);


    // The following function calls have been added as a structure to a 
    // potential solution demonstrating the core functionality. Feel free to 
    // add, remove or otherwise edit. Note that if you are creating a system 
    // for user-interaction the following lines will almost certainly need to 
    // be removed/altered.

    // Register the given user. As handed out, this line will run every time 
    // this client starts, and so should be removed if user interaction is 
    // added
    register_user(username, password, user_salt);

    // Retrieve the smaller file, that doesn't not require support for blocks. 
    // As handed out, this line will run every time this client starts, and so 
    // should be removed if user interaction is added
    get_file(username, password, user_salt, "tiny.txt");

    // Retrieve the larger file, that requires support for blocked messages. As
    // handed out, this line will run every time this client starts, and so 
    // should be removed if user interaction is added
    get_file(username, password, user_salt, "hamlet.txt");

    exit(EXIT_SUCCESS);
}
