#ifndef PE_PARSER_H
#define PE_PARSER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "global_def.h"
#include "elf.h"
#include <windows.h>

enum ELF_BIT_SIZE{
    ELF_BIT_SIZE_NONE,
    ELF_BIT_SIZE_32,
    ELF_BIT_SIZE_64
};

int LoadFile(const char *path, unsigned char **pFileBuffer, unsigned int *size);
int CheckDosHeaderMagic(WORD magic);
int CheckPeHeaderMagic(DWORD Signature);

int CheckElfHeaderMagic(DWORD magic);
ELF_BIT_SIZE CheckElfBitSize(unsigned char *ident);

#endif // PE_PARSER_H
