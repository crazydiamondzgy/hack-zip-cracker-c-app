#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <windows.h>

#include "../utils.h"
#include "crc32.h"
#include "zip.h"
#define REGPARAM
#define MAX_PW		40	/* should be low, but conservative.  */
#define BENCHMARK_LOOPS 5000000
#define FILE_SIZE	12
#define CRC_SIZE	2
#define HEADER_SIZE	(FILE_SIZE+CRC_SIZE)
#define MAX_FILES	8

#define DEVNULL ">NUL 2>&1"

u8 pw[MAX_PW + 1] = "aaaaaa";
u8 *pw_end;			/* must point to the trailing zero byte.  */

u8 files[MAX_FILES * HEADER_SIZE];
const char *file_path[MAX_FILES];
int file_count;
int verbosity;
u8 mult_tab[16384];

static u32 fgetu32 (FILE * f)
{
	return (fgetc (f) << 0) |
		(fgetc (f) << 8) |
		(fgetc (f) << 16) |
		(fgetc (f) << 24);
}

static u32 fgetu16 (FILE * f)
{
	return (fgetc (f) << 0) |
		(fgetc (f) << 8);
}

static int
zip_open(CrackContext *ctx)
{
	FILE *f = fopen (ctx->input_filename, "rb");
	u16 t;
	
	if (!f)
    {
		fprintf (stderr, "skipping '%s': %s\n", ctx->input_filename, strerror (errno));
		goto out;
    }
	
	while (!feof (f))
    {
		u32 id = fgetu32 (f);
		
		if (id == 0x04034b50UL)
		{
			u16 version = fgetu16 (f);
			u16 flags = fgetu16 (f);
			u16 compression_method = fgetu16 (f);
			u16 lastmodtime = fgetu16 (f);
			u16 lastmoddate = fgetu16 (f);
			u32 crc32 = fgetu32 (f);
			u32 compr_size = fgetu32 (f);
			u32 uncompr_size = fgetu32 (f);
			u16 name_len = fgetu16 (f);
			u16 extra_field_len = fgetu16 (f);
			
			char zip_path[1024];
			
			/* these are unused.  */
			(void) lastmoddate;
			(void) lastmodtime;
			(void) compression_method;
			(void) version;
			
			if (name_len < 1024)
			{
				fread (zip_path, name_len, 1, f);
				zip_path[name_len] = 0;
			}
			else
			{
				fprintf (stderr, "filename too long (>1023 bytes), skipping zipfile\n");
				goto out;
			}
			
			fseek (f, extra_field_len, SEEK_CUR);
			
			if (flags & 1)
			{
				if (compr_size >= 12)
				{
					u8 *file = files + HEADER_SIZE * file_count;
					fread (file, FILE_SIZE, 1, f);
					
					if (flags & 8)
                    {
						/* extended header format? */
						file[FILE_SIZE] = lastmodtime >> 8;
						file[FILE_SIZE + 1] = lastmodtime;
                    }
					else
                    {
						file[FILE_SIZE] = crc32 >> 24;
						file[FILE_SIZE + 1] = crc32 >> 16;
                    }
					
					file_path[file_count] = strdup (ctx->input_filename);
					
					if (verbosity)
						printf ("found file '%s', (size cp/uc %6lu/%6lu, flags %lx, chk %02x%02x)\n",
						zip_path, (unsigned long) compr_size, (unsigned long) uncompr_size, (unsigned long) flags,
						file[FILE_SIZE], file[FILE_SIZE+1]);
					
					if (++file_count >= MAX_FILES)
					{
						if (verbosity)
							printf ("%d file maximum reached, skipping further files\n", MAX_FILES);
						
						goto out;
					}
					
					compr_size -= 12;
				}
				else
				{
					fprintf (stderr, "'%s' is corrupted, skipping zipfile\n", zip_path);
					goto out;
				}
			}
			else if (verbosity)
				printf ("'%s' is not encrypted, skipping\n", zip_path);
			
			fseek (f, compr_size, SEEK_CUR);
		}
		else if (id == 0x08074b50UL)	/* extended local sig (?)  */
		{
			fseek (f, 12, SEEK_CUR);
		}
		else if (id == 0x30304b50UL)
		{
			/* ignore */
		}
		else if (id == 0x02014b50UL || id == 0x06054b50UL)
		{
			goto out;
		}
		else
		{
			fprintf (stderr, "found id %08lx, '%s' is not a zipfile ver 2.xx, skipping\n", (unsigned long) id, ctx->input_filename);
			goto out;
		}
    }
	
out:
	fclose (f);
	
	
	if (file_count == 0)
    {
		fprintf (stderr, "no usable files found\n");
		exit (1);
    }
	
	for (t = 0; t < 16384; t++)
		mult_tab[t] = ((t*4+3) * (t*4+2) >> 8) & 0xff;

	return 0;
}

static int
zip_crack(CrackContext *ctx, char *string, unsigned int len)
{
	int changed = -1;
	int crack_count = 0;
	u32 key_stack[(MAX_PW+1) * 3] = { 0x12345678UL, 0x23456789UL, 0x34567890UL };
	u32 *sp = 0;
	int count = file_count;
	int count2 = 0;
	u32 key0, key1, key2;
	u8 *p;
	u8 *b = files;
	
	strcpy(pw, string);
	changed = -1;
	if (changed < 0)
	{
		changed = strlen (pw);
		pw_end = pw + changed;
		sp = key_stack + changed * 3;
	}
	
	sp -= changed * 3;
	p = (u8 *)pw_end - changed;
	
	key0 = *sp++;
	key1 = *sp++;
	key2 = *sp++;
	do {
		*sp++ = key0 = crc32 (key0, *p++);
		*sp++ = key1 = (key1 + (u8)key0) * 134775813 + 1;
		*sp++ = key2 = crc32 (key2, key1 >> 24);
	} while (*p);
	
	sp -= 3;
	
	do
	{
		u8 target, pre_target;
		u32 kez0, kez1, kez2;
		u8 *e = b + FILE_SIZE - 1;
		
		kez0 = key0, kez1 = key1, kez2 = key2;
		do
		{
			pre_target = *b++ ^ mult_tab [(u16)(kez2) >> 2];
			
			kez0 = crc32 (kez0, pre_target);
			kez1 = (kez1 + (u8)kez0) * 134775813 + 1;
			kez2 = crc32 (kez2, kez1 >> 24);
		}
		while (b < e);
		
		target = *b++ ^ mult_tab [(u16)(kez2) >> 2];
		
		if (target != *b++)
			goto out;
		
		if (pre_target == *b++)
			count2++;
	}
	while(--count);
	
	//
	// 检查是否能用 unzip 解开
	//
	{
		char buff[1024];
		int status;
		TCHAR szFilePath[MAX_PATH + 1]; 
		GetModuleFileName(NULL, szFilePath, MAX_PATH); 
		(strrchr(szFilePath, '\\'))[1] = 0;
		strcat(szFilePath, "unzip.exe");

		sprintf (buff, "%s -qqtP \"%s\" %s ", szFilePath, pw, file_path[0]);
		status = system (buff);
		
		if (status == EXIT_SUCCESS)
		{
			strcpy(ctx->pw, pw);
			return 1;
		}
	}
out:	
	return 0;
}

static int
zip_close(CrackContext *ctx)
{
	return 0;
}

Cracker zip_cracker = 
{
	"matrix zip cracker", 
	"zip", 
	CRACK_TYPE_DICTIONARY | CRACK_TYPE_BRUTEFORCE, 
    CRACK_ID_ZIP, 
	0, 
	zip_open, 
	zip_crack, 
	zip_close, 
	NULL
};
