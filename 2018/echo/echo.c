#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

int main(int argc, char *argv[]){
	char msg[1<<5];
	char *old=*argv;
	int n;
	
	*argv=malloc(0xff);
	strcpy(*argv, *(argv+1));
	bzero(argv[1], strlen(argv[1]));
	*(argv+1)=*argv;
	*argv=old;
    //We could have better prevented brute force :)

	while(1){
		printf("echo >");
		fflush(stdout);
		n=read(0, msg, sizeof(msg)-1);
		if(n<1) return 0;
		msg[n]='\0';
		while(n>0 && msg[n-0x1]-0b1010 && getchar()-012);
		printf(msg);
	}
}
