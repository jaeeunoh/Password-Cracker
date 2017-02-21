#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

// Use this struct to pass arguments to our threads
typedef struct thread_args {
  int arg;
} thread_args_t;

// use this struct to receive results from our threads
typedef struct thread_result {
  int result;
} thread_result_t;

/**
 * This is our thread function. When we call pthread_create with this as an argument
 * a new thread is created to run this thread in parallel with the program's main
 * thread. When passing parameters to thread functions or accepting return values we
 * have to jump through a few hoops because POSIX threads can only take and return
 * a void*.
 */
void* thread_fn(void* void_args) {
  // Case the args pointer to the appropriate type and print our argument
  thread_args_t* args = (thread_args_t*)void_args;
  printf("Thread called with argument %d\n", args->arg);
  
  // Allocate memory to hold our return value
  thread_result_t* result = (thread_result_t*)malloc(sizeof(thread_result_t));
  result->result = args->arg * 100;
  
  // Return the pointer to allocated memory to our parent thread.
  return result;
}

int main(int argc, char** argv) {
  // You'll have to move over any code from partB that you would like to use.
  // Here's a quick little thread demo.
  pthread_t thread1;
  pthread_t thread2;
  
  // Make two structs so we can pass arguments to our threads
  thread_args_t thread1_args;
  thread_args_t thread2_args;
  
  // Set thread arguments
  thread1_args.arg = 1;
  thread2_args.arg = 2;
  
  // Create thread 1. We just pass in the address of our args struct so thread1 can acess it
  if(pthread_create(&thread1, NULL, thread_fn, &thread1_args) != 0) {
    perror("Error creating thread 1");
    exit(2);
  }
  
  // Do the same for thread 2
  if(pthread_create(&thread2, NULL, thread_fn, &thread2_args) != 0) {
    perror("Error creating thread 2");
    exit(2);
  }
  
  // Make pointers to the thread result structs that our threads will write into
  thread_result_t* thread1_result;
  thread_result_t* thread2_result;
  
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
  
  // Show the results
  printf("Thread 1 returned %d\n", thread1_result->result);
  printf("Thread 2 retunred %d\n", thread2_result->result);
  
  // Free the result structs, which were originally allocated in our threads
  free(thread1_result);
  free(thread2_result);
}
