#define _GNU_SOURCE
#include <openssl/md5.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <math.h> 

#define MAX_USERNAME_LENGTH 24
#define PASSWORD_LENGTH 6

typedef struct password_entry {
  char username[MAX_USERNAME_LENGTH+1];
  uint8_t password_md5[MD5_DIGEST_LENGTH+1];
  bool cracked;
  struct password_entry* next;
} password_entry_t;

password_entry_t* read_password_file(const char* filename);
int md5_string_to_bytes(const char* md5_string, uint8_t* bytes);
void print_md5_bytes(const uint8_t* bytes);
void generate_plain_text(int number, char text[]);

int main(int argc, char** argv) {
  char text[6] = {'a', 'a', 'a', 'a', 'a', 'a'};
  uint8_t password_ciphertext[MD5_DIGEST_LENGTH];
  
  if(argc != 2) {
    fprintf(stderr, "Usage: %s <path to password directory file>\n", argv[0]);
    exit(1);
  }
  
  // Read in the password file
  password_entry_t* passwords = read_password_file(argv[1]);

  
  int counter = 0;
  int max = pow(26, 6);
  // Now compute the MD5 hash of the string "password"
  while (counter < max) {
    MD5((unsigned char*)text, strlen(text), password_ciphertext);
    // Check if the two hashes are equal

    password_entry_t* current = passwords;
    while(current != NULL && !current->cracked) {
      if (memcmp(current->password_md5, password_ciphertext, MD5_DIGEST_LENGTH) == 0) {
        current->cracked = 0;
        for (int j = 0; j < MAX_USERNAME_LENGTH+1; j++) {
          printf ("%c", current->username[j]);
        }
        printf (" "); 
        for (int i = 0; i < 6; i++) {
          printf ("%c", text[i]);
        }
        printf ("\n"); 
      }
      current = current->next;
    }
    generate_plain_text(counter++, text); 
  }

    /*
    // Print the hash that was passed in as a command line argument
    printf("You passed in the hash ");
    print_md5_bytes(input_ciphertext);
    printf("\n");
  
    // Print the hash of "password"
    printf("The MD5 hash of \"%s\" is ", plaintext);
    print_md5_bytes(password_ciphertext);
    printf("\n");
    */ 

    return 0;
  }

  //Generate the string associated with a given integer. 
  void generate_plain_text(int number, char text[]) {
    int slot = number;
    int i = 0;
    //for(int i = 0; i < 6; i++){
    while(slot != 0){
      text[i] = (char) (97 + slot % 26);
      slot = slot / 26;
      i++;
    }
    return;
  }

  /**
   * Read a file of username and MD5 passwords. Return a linked list
   * of entries.
   * \param filename  The path to the password file
   * \returns         A pointer to the first node in the password list
   */
  password_entry_t* read_password_file(const char* filename) {
    // Open the password file
    FILE* password_file = fopen(filename, "r");
    if(password_file == NULL) {
      perror("opening password file");
      exit(2);
    }
  
    // Keep track of the current list
    password_entry_t* list = NULL;
  
    // Read until we hit the end of the file
    while(!feof(password_file)) {
      // Make space for a new node
      password_entry_t* newnode = (password_entry_t*)malloc(sizeof(password_entry_t));
    
      // Make space to hold the MD5 string
      char md5_string[MD5_DIGEST_LENGTH * 2 + 1];
    
      // Try to read. The space in the format string is required to eat the newline
      if(fscanf(password_file, "%s %s ", newnode->username, md5_string) != 2) {
        fprintf(stderr, "Error reading password file: malformed line\n");
        exit(2);
      }
    
      // Convert the MD5 string to MD5 bytes in our new node
      if(md5_string_to_bytes(md5_string, newnode->password_md5) != 0) {
        fprintf(stderr, "Error reading MD5\n");
        exit(2);
      }
    
      // Add the new node to the front of the list
      newnode->next = list;
      list = newnode;
    }
  
    return list;
  }

  /**
   * Convert a string representation of an MD5 hash to a sequence
   * of bytes. The input md5_string must be 32 characters long, and
   * the output buffer bytes must have room for MD5_DIGEST_LENGTH
   * bytes.
   *
   * \param md5_string  The md5 string representation
   * \param bytes       The destination buffer for the converted md5 hash
   * \returns           0 on success, -1 otherwise
   */
  int md5_string_to_bytes(const char* md5_string, uint8_t* bytes) {
    // Check for a valid MD5 string
    if(strlen(md5_string) != 2 * MD5_DIGEST_LENGTH) return -1;
  
    // Start our "cursor" at the start of the string
    const char* pos = md5_string;
  
    // Loop until we've read enough bytes
    for(size_t i=0; i<MD5_DIGEST_LENGTH; i++) {
      // Read one byte (two characters)
      int rc = sscanf(pos, "%2hhx", &bytes[i]);
      if(rc != 1) return -1;
    
      // Move the "cursor" to the next hexadecimal byte
      pos += 2;
    }
  
    return 0;
  }

  /**
   * Print a byte array that holds an MD5 hash to standard output.
   * 
   * \param bytes   An array of bytes from an MD5 hash function
   */
  void print_md5_bytes(const uint8_t* bytes) {
    for(size_t i=0; i<MD5_DIGEST_LENGTH; i++) {
      printf("%hhx", bytes[i]);
    }
  }
