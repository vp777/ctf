#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/user.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#define DEBUG 0

int do_child(int argc, char **argv);
int do_trace(pid_t child);
int wait_for_fpe(pid_t child);

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s FLAG\n", argv[0]);
        exit(1);
    }

    /*if (ptrace(PTRACE_TRACEME)<0){
        printf("Debugger detected, closing\n");
        exit(0);
    }*/

    pid_t child = fork();
    if (child == 0) {
        return do_child(argc, argv);
    } else {
        return do_trace(child);
    }
}

int do_child(int argc, char **argv) {
    static char verify[27]={18,244,152,173,84,173,244,88,84,221,173,32,152,142,88,84,247,146,84,135,113,247,243,135,84,113,243};
    #if DEBUG==1
    static char result[27];
    #endif
    char a,b;
    int length_check=0;
    unsigned int invalid_flag=0, temp, res;
    
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    kill(getpid(), SIGSTOP);
    
    for(int i=0;i<strlen(argv[1]);i++){
        b=argv[1][i];
        a=(2*b)%b; //could use some obfuscation
        res=b/a;
        res^=argv[1][i];
        
        //check if res==verify[i%27]
        if(res<verify[i]) res=verify[i%27]+1;
        invalid_flag|=__builtin_uadd_overflow(4294967295U-verify[i%27], res, &temp);
        length_check|=(1<<i);
        
        #if DEBUG==1
        if(i<27){
            result[i]=res;
            printf("Result [%d]=%d\n", i, result[i]);
        }
        #endif
    }
    #if DEBUG==1
    for(int i=0;i<27;i++) printf("[%d] %d\n", i, result[i]);
    #endif
    if(!invalid_flag && length_check==0x7ffffff) //length 27
        printf("The flag is: CYCTF{%s}\n", argv[1]);
    return 0;
}


int do_trace(pid_t child) {
    static char lookup_table[256]={99,
 244, 171, 200, 142, 121, 96, 34, 38, 76, 57, 110, 23, 91, 51, 3, 141, 168, 145, 87, 15, 143, 28, 253, 206, 158, 67, 147, 58, 123, 215, 68, 42, 13, 120, 113, 190, 236, 25, 196, 1, 184, 18, 20, 39, 106, 64, 80, 65, 198, 138, 107, 172, 167, 177, 154, 69, 14, 70, 239, 102, 185, 26, 78, 148, 29, 139, 21, 224, 169, 98, 7, 8, 36, 178, 219, 60, 89, 235, 164, 153, 116, 201, 75, 161, 114, 95, 193, 115, 119, 6, 100, 245, 61, 246, 11, 118, 221, 53, 237, 85, 93, 44, 254, 156, 238, 210, 197, 130, 49, 157, 109, 173, 74, 82, 211, 105, 151, 111, 101, 50, 52, 242, 17, 47, 71, 249, 183, 140, 247, 176, 0, 135, 227, 192, 195, 88, 234, 32, 213, 54, 137, 152, 191, 214, 94, 19, 230, 217, 243, 220, 129, 255, 231, 46, 155, 45, 204, 203, 188, 66, 166, 209, 128, 228, 79, 4, 5, 30, 56, 127, 187, 132, 10, 9, 199, 251, 73, 77, 126, 12, 233, 31, 92, 133, 117, 125, 144, 159, 150, 208, 222, 40, 35, 182, 59, 194, 104, 163, 174, 223, 103, 112, 146, 212, 207, 2, 216, 83, 86, 55, 165, 179, 27, 162, 24, 240, 225, 81, 90, 189, 229, 108, 181, 226, 134, 63, 170, 232, 252, 41, 33, 136, 72, 97, 202, 241, 22, 218, 186, 160, 131, 122, 124, 180, 149, 205, 84, 16, 48, 175, 62, 37, 250, 43, 248};
    struct user_regs_struct regs;
    int status;
    
    waitpid(child, &status, 0);
    while(1) {
        if (wait_for_fpe(child) != 0) break;
        ptrace(PTRACE_GETREGS, child, NULL, &regs);
        regs.rip+=2;
        #if DEBUG==1
        printf("Parent-> received %d\n", regs.rax);
        #endif
        regs.rax=lookup_table[regs.rax];
        ptrace(PTRACE_SETREGS, child, NULL, &regs);
    }
    return 0;
}

int wait_for_fpe(pid_t child) {
    int status;
    while (1) {
        ptrace(PTRACE_CONT, child, 0, 0);
        waitpid(child, &status, 0);
        #if DEBUG==1
        printf("Parent received from child %d\n", WSTOPSIG(status));
        #endif
        if (WIFSTOPPED(status) && !(WSTOPSIG(status)&(~(1<<3))) && WSTOPSIG(status)&(1<<3))//signal==8
            return 0;
        if (WIFEXITED(status))
            return 1;
    }
}