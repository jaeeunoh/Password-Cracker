#define _GNU_SOURCE
#include <openssl/md5.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <math.h>

#define PASSWORD_LENGTH 6

int md5_string_to_bytes(const char* md5_string, uint8_t* bytes);
void print_md5_bytes(const uint8_t* bytes);
void generate_plain_text();
bool compare(char x[], char y[], int size);

int main(int argc, char** argv) {
  char text[6] = {'a', 'a', 'a', 'a', 'a', 'a'};
  if(argc != 2) {
    fprintf(stderr, "Usage: %s <md5 sum of %d character password>\n", argv[0], PASSWORD_LENGTH);
    exit(1);
  }
  
  // This will hold the bytes of our md5 hash input
  uint8_t input_ciphertext[MD5_DIGEST_LENGTH];
  
  // Convert the string representation of the MD5 hash to a byte array
  md5_string_to_bytes(argv[1], input_ciphertext);
  
  // Now compute the MD5 hash of "passwd" (you should change this if you change PASSWORD_LENGTH)
  char* plaintext = "passwd";
  uint8_t password_ciphertext[MD5_DIGEST_LENGTH];

  int counter = 0;
  int max = pow(26, 6);
  // Now compute the MD5 hash of the string "password"
  while (counter < max) {
    MD5((unsigned char*)text, strlen(text), password_ciphertext);
    generate_plain_text(counter++, text);
    // Check if the two hashes are equal
    if(memcmp(input_ciphertext, password_ciphertext, MD5_DIGEST_LENGTH) == 0) {
      printf("Those two hashes are equal!\n");
      break;
    }
    //else {
    //  printf("Those hashes are not equal.\n");
    //}
  } 

  // Print the hash that was passed in as a command line argument
  printf("You passed in the hash ");
  print_md5_bytes(input_ciphertext);
  printf("\n");
  
  // Print the hash of "password"
  printf("The MD5 hash of \"%s\" is ", plaintext);
  print_md5_bytes(password_ciphertext);
  printf("\n");

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
