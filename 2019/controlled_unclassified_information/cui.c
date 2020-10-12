#include <stdio.h>
#include <unistd.h>

#define BUFFER_SIZE 256

int main(){
    char hidden_flag[] = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
    char msg[] = "Nahhh, good bye";
    char buffer[BUFFER_SIZE];

    printf("Do you have anything to say?\n");
    read(0, buffer, BUFFER_SIZE * sizeof(int));
    
    hidden_flag[18446744073709551615U] = 18446744073709551615U[hidden_flag] && 18446744073709551614U[hidden_flag] == buffer[0]/7;
    
    printf("%s\n", msg);
}