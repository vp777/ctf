#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/user.h>
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>

#define DEBUG 0

//https://gist.github.com/jorendorff/cd18d77bd1cf1d2b40af
//https://github.com/intel/ikgt-core/blob/master/core/vmexit/vmexit_task_switch.c
enum {
    DR7_BREAK_ON_EXEC  = 0,
    DR7_BREAK_ON_WRITE = 1,
    DR7_BREAK_ON_RW    = 3,
};

enum {
    DR7_LEN_1,
    DR7_LEN_2,
    DR7_LEN_8, //not widely supported
    DR7_LEN_4,
};

enum {
    STATE_TERMINATED,
    STATE_TRAP,
    STATE_SECCOMP,
    STATE_UNKNOWN,
};

typedef union {
    uint32_t value;
    struct {
        uint32_t l0:1;         /* bit 0 local b.p. enable */
        uint32_t g0:1;         /* bit 1 global b.p. enable */
        uint32_t l1:1;         /* bit 2 local b.p. enable */
        uint32_t g1:1;         /* bit 3 global b.p. enable */
        uint32_t l2:1;         /* bit 4 local b.p. enable */
        uint32_t g2:1;         /* bit 5 global b.p. enable */
        uint32_t l3:1;         /* bit 6 local b.p. enable */
        uint32_t g3:1;         /* bit 7 global b.p. enable */
        uint32_t le:1;         /* bit 8 local exact b.p. enable */
        uint32_t ge:1;         /* bit 9 global exact b.p. enable */
        uint32_t rsvd_12_10:3; /* bits 12:10 reserved */
        uint32_t gd:1;         /* bit 13 general detect enable */
        uint32_t rsvd_15_14:2; /* bits 15:14 reserved */
        uint32_t rw0:2;        /* bits 17:16 */
        uint32_t len0:2;       /* bits 19:18 */
        uint32_t rw1:2;        /* bits 21:20 */
        uint32_t len1:2;       /* bits 23:22 */
        uint32_t rw2:2;        /* bits 25:24 */
        uint32_t len2:2;       /* bits 27:26 */
        uint32_t rw3:2;        /* bits 29:28 */
        uint32_t len3:2;       /* bits 31:30 */
    };
} dr7_t;

#define PT_EXIT_ON_ERROR(expr, msg) do { \
    if ((expr)==-1) {                    \
        perror(msg);                     \
        exit(-1);                        \
    }                                    \
} while(0)

int do_trace(pid_t child);
int wait_for_fpe(pid_t child);

int main(int argc, char **argv) {
    pid_t child = fork();

    if (child == 0) {
        if (ptrace(PTRACE_TRACEME) != -1) {
            //raise(SIGSTOP);
            execl(argv[1], argv[1], NULL);
        }
    } else {
        return do_trace(child);
    }
}

int do_trace(pid_t child) {
    struct user_regs_struct regs;
    int status;
    
    waitpid(child, &status, 0);
    if(ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL) == -1){
        perror("Setting EXITKILL");
        goto KILL_CHILD;
    }
    
    if ((status = wait_for_fpe(child)) != STATE_TRAP) 
        goto ABORTING;
    
    PT_EXIT_ON_ERROR(ptrace(PTRACE_GETREGS, child, NULL, &regs), "Getting Regs");
    regs.rip+=1;
    PT_EXIT_ON_ERROR(ptrace(PTRACE_SETREGS, child, NULL, &regs), "Setting Regs");

    uint64_t addr = regs.rsi;
    addr += 3;
    addr &= ~3LLU;
    PT_EXIT_ON_ERROR(ptrace(PTRACE_POKEUSER, child, offsetof(struct user, u_debugreg[0]), addr+4), "Setting DR0");    
    PT_EXIT_ON_ERROR(ptrace(PTRACE_POKEUSER, child, offsetof(struct user, u_debugreg[1]), addr+8), "Setting DR1");    
    PT_EXIT_ON_ERROR(ptrace(PTRACE_POKEUSER, child, offsetof(struct user, u_debugreg[2]), addr+12), "Setting DR2");    
    PT_EXIT_ON_ERROR(ptrace(PTRACE_POKEUSER, child, offsetof(struct user, u_debugreg[3]), addr+16), "Setting DR3");    
    
    dr7_t dr7 = {0};
    dr7.l0 = 1;
    dr7.g0 = 1;
    dr7.rw0 = DR7_BREAK_ON_RW;
    dr7.len0 = DR7_LEN_4;
    
    dr7.l1 = 1;
    dr7.g1 = 1;
    dr7.rw1 = DR7_BREAK_ON_RW;
    dr7.len1 = DR7_LEN_4;

    dr7.l2 = 1;
    dr7.g2 = 1;
    dr7.rw2 = DR7_BREAK_ON_RW;
    dr7.len2 = DR7_LEN_4;
    
    dr7.l3 = 1;
    dr7.g3 = 1;
    dr7.rw3 = DR7_BREAK_ON_RW;
    dr7.len3 = DR7_LEN_4;
   
    PT_EXIT_ON_ERROR(ptrace(PTRACE_POKEUSER, child, offsetof(struct user, u_debugreg[7]), dr7), "Setting DR7");

    if ((status = wait_for_fpe(child)) != STATE_TERMINATED) 
        goto ABORTING;

    return 0;

ABORTING:;
    uint32_t dr6 = 0;

    errno = 0;
    dr6 = (uint32_t) ptrace(PTRACE_PEEKUSER, child, offsetof(struct user, u_debugreg[6]), 0); //could zero dr6 afterwards

    if (!errno && (dr6 & 15))
        printf("I am out, the flag is not directly accessible\n");
    else if (status == STATE_SECCOMP)
        printf("A lot of syscalls are supported, but not the one you specified\n");
    else
        printf("Aborting, mixed signals\n");

KILL_CHILD:
    while(kill(child, SIGKILL)==-1);

    return 1;
}

int wait_for_fpe(pid_t child) {
    int status, child_signal=0, retval;
    while (1) {
        ptrace(PTRACE_CONT, child, 0, child_signal);
        //ptrace(PTRACE_SYSCALL, child, 0, child_signal);
        retval = waitpid(child, &status, 0);

        if (DEBUG)
            printf("retval, status and stopsig received from tracee: %d %d %d\n", retval, status, WSTOPSIG(status));

        if (retval == -1)
            return STATE_UNKNOWN;

        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP)
            return STATE_TRAP;

        if (status & (1 << PTRACE_EVENT_SECCOMP)) //?
            return STATE_SECCOMP;

        if (WIFEXITED(status) || WIFSIGNALED(status))
            return STATE_TERMINATED;
       
        child_signal = WIFSTOPPED(status)?WSTOPSIG(status):0;
    }
}
