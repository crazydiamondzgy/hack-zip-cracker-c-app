#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdio.h>
#include <string.h>


typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned short u16;
#define REGPARAM
#define MAX_PW		40	/* should be low, but conservative.  */
#define BENCHMARK_LOOPS 5000000
#define FILE_SIZE	12
#define CRC_SIZE	2
#define HEADER_SIZE	(FILE_SIZE+CRC_SIZE)
#define MAX_FILES	8

extern u8 pw[MAX_PW+1];
extern u8 *pw_end;

extern int verbosity;

extern u8 files[MAX_FILES*HEADER_SIZE];
extern const char *file_path[MAX_FILES];
extern int file_count;

void 
init_zip(void * pImageFeather, int iElementCountFeather, int iElementSizeFeather);

void
conv_zip(void * pFile, void * pMem);

void
iconv_zip(void * pStr, void * pMem);

void * 
crack_zip(char *string, unsigned int len);

#ifdef __cplusplus
}
#endif