#define _GNU_SOURCE
#include <pthread.h>
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
  struct password_entry* previous;  
} password_entry_t;

password_entry_t* read_password_file(const char* filename);
int md5_string_to_bytes(const char* md5_string, uint8_t* bytes);
void print_md5_bytes(const uint8_t* bytes);
void generate_plain_text(int number, char text[]);
void* find_passwords(void* args);

// Use this struct to pass arguments to our threads
typedef struct thread_args {
  int start;
  password_entry_t* entry; 
} thread_args_t;

// use this struct to receive results from our threads
typedef struct thread_result {
  int result;
} thread_result_t;


int main(int argc, char** argv) {
  if(argc != 2) {
    fprintf(stderr, "Usage: %s <path to password directory file>\n", argv[0]);
    exit(1);
  }
  password_entry_t* passwords = read_password_file(argv[1]);  
  // You'll have to move over any code from partB that you would like to use.
  // Here's a quick little thread demo.
  pthread_t thread1;
  pthread_t thread2;
  pthread_t thread3;
  pthread_t thread4;
  
  // Make two structs so we can pass arguments to our threads
  thread_args_t thread1_args;
  thread_args_t thread2_args;
  thread_args_t thread3_args;
  thread_args_t thread4_args;
  
  // Set thread arguments
  thread1_args.start = 0;
  thread2_args.start = pow (26, 6) / 4;
  thread3_args.start = (pow (26, 6) / 4) * 2;
  thread4_args.start = (pow (26, 6) / 4) *3;

  thread1_args.entry = passwords;
  thread2_args.entry = passwords;
  thread3_args.entry = passwords;
  thread4_args.entry = passwords;
  
  // Create thread 1. We just pass in the address of our args struct so thread1 can acess it
  if(pthread_create(&thread1, NULL, find_passwords, &thread1_args) != 0) {
    perror("Error creating thread 1");
    exit(2);
  }
  
  // Do the same for thread 2
  if(pthread_create(&thread2, NULL, find_passwords, &thread2_args) != 0) {
    perror("Error creating thread 2");
    exit(2);
  }
  
  // Do the same for thread3 
  if(pthread_create(&thread3, NULL, find_passwords, &thread3_args) != 0) {
    perror("Error creating thread 3");
    exit(2);
  }

  // Do the same for thread 4
  if(pthread_create(&thread4, NULL, find_passwords, &thread4_args) != 0) {
    perror("Error creating thread 4");
    exit(2);
  }
  
  // Make pointers to the thread result structs that our threads will write into
  thread_result_t* thread1_result;
  thread_result_t* thread2_result;
  thread_result_t* thread3_result;
  thread_result_t* thread4_result;
  
  // Wait for thread 1
  if(pthread_join(thread1, (void**)&thread1_result) != 0) {
    perror("Error joining with thread 1");
    exit(2);
  }
 
  // Wait for thread 2
  if(pthread_join(thread2, (void**)&thread2_result) != 0) {
    perror("error joining with thread 2");
    exit(2);
  }

  // Wait for thread 3
  if(pthread_join(thread3, (void**)&thread3_result) != 0) {
    perror("error joining with thread 3");
    exit(2);
  }

  // Wait for thread 4
  if(pthread_join(thread4, (void**)&thread4_result) != 0) {
    perror("error joining with thread 4");
    exit(2);
  }
  
  // Free the result structs, which were originally allocated in our threads
  free(thread1_result);
  free(thread2_result);
  free(thread3_result);
  free(thread4_result);
}


void* find_passwords(void* args){
  char text[6] = {'a', 'a', 'a', 'a', 'a', 'a'}; 
  uint8_t password_ciphertext[MD5_DIGEST_LENGTH];
  int counter = ((thread_args_t*) args)->start;
  int max = counter + (pow(26, 6)/4);
  // Now compute the MD5 hash
  while (counter < max) {
    MD5((unsigned char*)text, strlen(text), password_ciphertext);
    // Check if the two hashes are equal
    password_entry_t* current = ((thread_args_t*) args)->entry;
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
        password_entry_t* holder = current->next;
        if(holder != NULL){
          holder->previous = current->previous;
        }
        if(current->previous != NULL){
          current->previous->next = holder;
        }
        current = holder;
      }
      else{current = current->next;}
    }
    generate_plain_text(counter++, text);
  }
  thread_result_t* result = (thread_result_t*)malloc(sizeof(thread_result_t));
  result->result = ((thread_args_t*) args)->start * 100;
  return result;
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
    if(list != NULL){list->previous = newnode;}
    newnode->previous = NULL;
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
