#define _GNU_SOURCE
#include <openssl/md5.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

int main(int argc, char** argv) {
  if(argc != 2) {
    fprintf(stderr, "Usage: %s <path to password directory file>\n", argv[0]);
    exit(1);
  }
  
  // Read in the password file
  password_entry_t* passwords = read_password_file(argv[1]);
  
  // Print some passwords
  password_entry_t* current = passwords;
  while(current != NULL) {
    printf("%s ", current->username);
    print_md5_bytes(current->password_md5);
    printf("\n");
    current = current->next;
  }
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
