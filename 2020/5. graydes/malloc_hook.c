//gcc -c -Wall -fpic malloc_hook.c;gcc -shared -o libmalloc_hook.so malloc_hook.o -lpthread
//LD_PRELOAD=$(pwd)/libmalloc_hook.so ./graydes -e asd test.txt output.txt

#include <stdio.h>
#include <malloc.h>
#include <pthread.h> 
#include <unistd.h>

//https://man7.org/linux/man-pages/man3/malloc_hook.3.html
static void *my_malloc_hook(size_t, const void *);
static void *(*old_malloc_hook)(size_t, const void *);
static void my_init_hook(void);
void (*__malloc_initialize_hook) (void) = my_init_hook;

static void
my_init_hook(void)
{
   old_malloc_hook = __malloc_hook;
   __malloc_hook = my_malloc_hook;
}

void delayed_reader(void *arg){
     usleep(5000);
     unsigned char *addr = arg;

     printf("[malloc_hook->%p]=", addr);
     for (int i=0;i<8;i++){
         printf("%02x", addr[i]);
     }
     printf("\n");
}

static void *
my_malloc_hook(size_t size, const void *caller)
{
   void *result;
   pthread_t tid; 

   __malloc_hook = old_malloc_hook;
   result = malloc(size);
   old_malloc_hook = __malloc_hook;
   printf("malloc(%u) called from %p returns %p\n",
           (unsigned int) size, caller, result);

   if (size == 8) 
       pthread_create(&tid, NULL, delayed_reader, result);

   __malloc_hook = my_malloc_hook;

   return result;
}
