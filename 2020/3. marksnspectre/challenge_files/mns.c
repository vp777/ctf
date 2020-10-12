#include <x86intrin.h>
#include <unistd.h>

#define D 512
#define AO_SIZE 128

typedef struct {
  char ad[256*D];
  char ao[AO_SIZE];
  size_t ao_size;
  char flag[32];
} GData;

static GData gdata = {.flag="CTF{flag should be here}", .ao_size=AO_SIZE};
char tmp;

void vaccess(size_t o){
    if (o<gdata.ao_size){
        tmp=gdata.ad[gdata.ao[o]*D];
    }
}

void flush(size_t o){
    _mm_clflush(&gdata.ad[o]);
}

void gaccess(size_t o){
    tmp = gdata.ad[o];
}

void mns_version(){
    const char msg[]="\
$$\\      $$\\                     $$\\                  $$$\\     $$$$$$\\                                  $$\\                         \n\
$$$\\    $$$ |                    $$ |                $$ $$\\   $$  __$$\\                                 $$ |                        \n\
$$$$\\  $$$$ | $$$$$$\\   $$$$$$\\  $$ |  $$\\  $$$$$$$\\ \\$$$\\ |  $$ /  \\__| $$$$$$\\   $$$$$$\\   $$$$$$$\\ $$$$$$\\    $$$$$$\\   $$$$$$\\  \n\
$$\\$$\\$$ $$ | \\____$$\\ $$  __$$\\ $$ | $$  |$$  _____|$$\\$$\\$$\\\\$$$$$$\\  $$  __$$\\ $$  __$$\\ $$  _____|\\_$$  _|  $$  __$$\\ $$  __$$\\ \n\
$$ \\$$$  $$ | $$$$$$$ |$$ |  \\__|$$$$$$  / \\$$$$$$\\  $$ \\$$ __|\\____$$\\ $$ /  $$ |$$$$$$$$ |$$ /        $$ |    $$ |  \\__|$$$$$$$$ |\n\
$$ |\\$  /$$ |$$  __$$ |$$ |      $$  _$$<   \\____$$\\ $$ |\\$$\\ $$\\   $$ |$$ |  $$ |$$   ____|$$ |        $$ |$$\\ $$ |      $$   ____|\n\
$$ | \\_/ $$ |\\$$$$$$$ |$$ |      $$ | \\$$\\ $$$$$$$  | $$$$ $$\\\\$$$$$$  |$$$$$$$  |\\$$$$$$$\\ \\$$$$$$$\\   \\$$$$  |$$ |      \\$$$$$$$\\ \n\
\\__|     \\__| \\_______|\\__|      \\__|  \\__|\\_______/  \\____\\__|\\______/ $$  ____/  \\_______| \\_______|   \\____/ \\__|       \\_______|\n\
                                                                        $$ |                                                        \n\
                                                                        $$ |                                                        \n\
                                                                        \\__|                                                        \n\
";
    write(1, msg, sizeof(msg));
}

static void __attribute__((constructor)) _init(){
    asm volatile ("int3"::"S"(&gdata.flag[0]):);
}

