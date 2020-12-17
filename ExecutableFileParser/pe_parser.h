#ifndef PE_PARSER_H
#define PE_PARSER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "global_def.h"
#include <windows.h>


int LoadFile(const char *path, unsigned char **pFileBuffer, unsigned int *size);
int CheckDosHeaderMagic(WORD magic);
int CheckPeHeaderMagic(DWORD Signature);
void PrintNTHeaders(const char *path);

#endif // PE_PARSER_H
