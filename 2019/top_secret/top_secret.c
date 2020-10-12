#include <stdio.h>
#include <unistd.h>
#include <xmmintrin.h>

#define BUFFER_SIZE 256

int main(){
    char hidden_flag[] = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
    char msg[] = "Nahhh, good bye";
    char * volatile msg_ptr = msg;
    char buffer[BUFFER_SIZE];
    __m128 ver = _mm_load_ps((float const*)hidden_flag);

    printf("Do you have anything to say?\n");
    read(0, buffer, BUFFER_SIZE * sizeof(int));
    printf("%s\n", msg_ptr);
}