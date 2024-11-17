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
#include <time.h> 
#include <sys/time.h> 
#include <stdbool.h>> 



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
    //char response_buffer[MAXBUF]; // Buffer til at modtage data

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
    message[length] = '\0';  

    printf("Server response (Block %d/%d, Status: %d): %s\n", 
           block_id + 1, blocks_count, status, message);

    close(sockfd);
}

void save_salt(const char* username, const char* salt) {
    // Åbner filen "salts.txt" i append-tilstand
    FILE* file = fopen("salts.txt", "a"); 
    if (file == NULL) { 
        // Hvis filen ikke kan åbnes, udskriv en fejlmeddelelse og afslut programmet
        perror("Failed to open salt file");
        exit(EXIT_FAILURE);
    }
    // Skriver brugernavn og salt i formatet "brugernavn:salt" til filen
    fprintf(file, "%s:%s\n", username, salt); 
    // Lukker filen efter skrivning
    fclose(file);
}

int load_salt(const char* username, char* salt) {
    // Åbner filen "salts.txt" i læsetilstand
    FILE* file = fopen("salts.txt", "r");
    if (!file) return 0; // Returnerer 0, hvis filen ikke findes

    // Variabler til at gemme linjen og midlertidige værdier for brugernavn og salt
    char line[256], file_username[USERNAME_LEN], file_salt[SALT_LEN + 1];

    // Læser hver linje fra filen, indtil der ikke er flere linjer
    while (fgets(line, sizeof(line), file)) {
        // Parser linjen i formatet "brugernavn:salt" og sammenligner brugernavn
        if (sscanf(line, "%15[^:]:%64s", file_username, file_salt) == 2 && strcmp(file_username, username) == 0) {
            // Hvis brugernavn matcher, kopier salt til output-parameteren
            strncpy(salt, file_salt, SALT_LEN); 
            salt[SALT_LEN] = '\0'; // Sikrer at salt-strengen er null-termineret
            fclose(file); // Lukker filen
            return 1; // Returnerer 1 for at indikere, at salt blev fundet
        }
    }

    // Lukker filen, hvis ingen match blev fundet
    fclose(file);
    return 0; // Returnerer 0 for at indikere, at der ikke blev fundet et match
}

/*
 * Get a file from the server by sending the username and signature, along with
 * a file path. Note that this function should be able to deal with both small 
 * and large files. 
 */
void get_file(char* username, char* password, char* salt, char* to_get) {
    hashdata_t hash;
    get_signature(password, salt, &hash);

    Request_t req;
    strncpy(req.header.username, username, USERNAME_LEN);
    memcpy(req.header.salted_and_hashed, hash, sizeof(hashdata_t));
    memcpy(req.payload, to_get, MAX_PAYLOAD);
    req.header.length = htobe32(strlen(req.payload));

    int sockfd;
    compsys_helper_state_t rio;

    if ((sockfd = compsys_helper_open_clientfd(server_ip, server_port)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    printf("Connected to server, sending file request...\n");
    compsys_helper_writen(sockfd, &req, sizeof(req));
    printf("Request sent, waiting for response...\n");

    compsys_helper_readinitb(&rio, sockfd);

    FILE* newfile = fopen(to_get, "wb");
    if (!newfile) {
        perror("Failed to open file for writing");
        close(sockfd);
        return;
    }

    uint32_t length, status, block_id, blocks_count;
    hashdata_t block_hash, total_hash;

    uint32_t expected_block_id = 0;

    char** block_buffer = calloc(1024, sizeof(char*));
    size_t* block_sizes = calloc(1024, sizeof(size_t));

    while (1) {
        if (compsys_helper_readnb(&rio, &length, sizeof(length)) <= 0) break;
        length = be32toh(length);

        if (compsys_helper_readnb(&rio, &status, sizeof(status)) <= 0) break;
        status = be32toh(status);

        if (compsys_helper_readnb(&rio, &block_id, sizeof(block_id)) <= 0) break;
        block_id = be32toh(block_id);

        if (compsys_helper_readnb(&rio, &blocks_count, sizeof(blocks_count)) <= 0) break;
        blocks_count = be32toh(blocks_count);

        compsys_helper_readnb(&rio, block_hash, SHA256_HASH_SIZE);
        compsys_helper_readnb(&rio, total_hash, SHA256_HASH_SIZE);

        char* message = malloc(length);
        if (!message) {
            perror("Memory allocation failed");
            break;
        }

        size_t bytes_read = 0;
        while (bytes_read < length) {
            ssize_t n = compsys_helper_readnb(&rio, message + bytes_read, length - bytes_read);
            if (n <= 0) {
                perror("Failed to read full block");
                free(message);
                fclose(newfile);
                close(sockfd);
                return;
            }
            bytes_read += n;
        }

        if (block_id == expected_block_id) {
            fwrite(message, 1, bytes_read, newfile);
            printf("Received and wrote block %d/%d\n", block_id + 1, blocks_count);
            free(message);
            expected_block_id++;

            while (block_buffer[expected_block_id]) {
                fwrite(block_buffer[expected_block_id], 1, block_sizes[expected_block_id], newfile);
                printf("Wrote buffered block %d/%d\n", expected_block_id + 1, blocks_count);
                free(block_buffer[expected_block_id]);
                block_buffer[expected_block_id] = NULL;
                expected_block_id++;
            }
        } else {
            block_buffer[block_id] = message;
            block_sizes[block_id] = bytes_read;
            printf("Buffered out-of-order block %d/%d\n", block_id + 1, blocks_count);
        }

        if (expected_block_id >= blocks_count) break;
    }

    free(block_buffer);
    free(block_sizes);

    fclose(newfile);
    close(sockfd);

    printf("File '%s' successfully received and saved in order.\n", to_get);
}
void generate_random_salt(char* salt, size_t size) {
    srand((unsigned int)time(NULL)); 
    // Genererer en tilfældig salt bestående af alfabetiske tegn
    for (size_t i = 0; i < size; i++) { 
        salt[i] = 'a' + (rand() % 26); // Tilfældig karakter mellem 'a' og 'z'
    }
    // Sikrer, at salt-strengen afsluttes med en null-terminator
    salt[size] = '\0'; 
}


int main(int argc, char **argv)
{
    char username[USERNAME_LEN];
    char password[PASSWORD_LEN];
    char user_salt[SALT_LEN+1];

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
    //strncpy(user_salt, 
    //    "0123456789012345678901234567890123456789012345678901234567890123\0", 
    //    SALT_LEN+1);
    if (!load_salt(username, user_salt)) { // CHANGE: Attempt to load salt for the provided username
        generate_random_salt(user_salt, SALT_LEN); // CHANGE: Generate random salt if none exists
        save_salt(username, user_salt); // CHANGE: Save new salt for future use
    }

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
    
    char fileLocation[PASSWORD_LEN];
    bool turnedOn = true;
    while (turnedOn) {
        printf("Enter file location (or type 'exit' to quit): ");
        scanf("%16s", fileLocation);
        if (strcmp(fileLocation, "exit") == 0) {
            turnedOn = false;
        } else {

        get_file(username, password, user_salt, fileLocation);
        }
    }
    
    exit(EXIT_SUCCESS);
}
