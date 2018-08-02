#include <stdio.h>
#include <unistd.h>
#include <string.h>

#define BSIZE 25

#define get_input(prompt, buffer, size) {	\
	printf(prompt);							\
	fflush(stdout);							\
	int n=read(0, buffer, size-1);			\
	if(n<1) return 0;						\
	buffer[n]=0;							\
} while(0)

extern void print_flag();

int authenticated_user(){
	char username[BSIZE], password[BSIZE];
	get_input("Username>", username, BSIZE);
	printf(username);
	fflush(stdout);
	get_input("Password>", password, BSIZE);
	printf(password);
	fflush(stdout);

	return username==password;
}

int main(int argc, char *argv[]){
	if(authenticated_user()) print_flag();
	else printf("Sorry, user could not be authenticated\n");
}
