#include <stdio.h>
#include <unistd.h>

extern void print_flag();

int main(int argc, char *argv[]){
	char buf[128];
	int n=read(0, buf, sizeof(buf)-1);
	if(n<1) return 0;
	buf[n]=0;
	printf(buf);
	if(isatty(fileno(stdin)))
		print_flag();
}
