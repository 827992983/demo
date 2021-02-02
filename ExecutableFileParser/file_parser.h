#ifndef PE_PARSER_H
#define PE_PARSER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "global_def.h"
#include "elf.h"
#include <windows.h>


int LoadFile(const char *path, unsigned char **pFileBuffer, unsigned int *size);
int CheckDosHeaderMagic(WORD magic);
int CheckPeHeaderMagic(DWORD Signature);

int CheckElfHeaderMagic(DWORD magic);

#endif // PE_PARSER_H
