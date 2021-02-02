#include "file_parser.h"
#include <QDebug>

int CheckDosHeaderMagic(WORD magic)
{
    if(magic != IMAGE_DOS_SIGNATURE)
    {
        return -1;
    }
    return 0;
}

int CheckPeHeaderMagic(DWORD Signature)
{
    if(Signature != IMAGE_NT_SIGNATURE){
        return -1;
    }
    return 0;
}

int LoadFile(const char *path, unsigned char **pFileBuffer, unsigned int *size)
{
    FILE *peFile = NULL;
    int fileSize = 0;


    peFile = fopen(path, "rb");
    if(!peFile){
        LOG_DEBUG("Open Pe File %s Error", path);
        return -1;
    }

    fseek(peFile, 0, SEEK_END);
    fileSize = ftell(peFile);
    fseek(peFile, 0, SEEK_SET);
    *pFileBuffer = (unsigned char *)malloc(fileSize);
    if(*pFileBuffer == NULL){
        LOG_DEBUG("Malloc Memory Error.");
        return -1;
    }

    size_t n = fread(*pFileBuffer, fileSize, 1, peFile);
    if(!n){
        LOG_DEBUG("Read File Error.");
        free(*pFileBuffer);
        *pFileBuffer = NULL;
        return -1;
    }
    *size = fileSize;
    fclose(peFile);

    LOG_DEBUG("Load File Size:%d", *size);
    return 0;
}


int CheckElfHeaderMagic(DWORD magic)
{
    if(magic != ELF_HEADER_SIGNATURE)
    {
        return -1;
    }
    return 0;
}


ELF_BIT_SIZE CheckElfBitSize(unsigned char *ident)
{
    if(ident == NULL){
        return ELF_BIT_SIZE_NONE;
    }

    if(ident[4] == 1){
        return ELF_BIT_SIZE_32;
    }else if(ident[4] == 2){
        return ELF_BIT_SIZE_64;
    }else{
        return ELF_BIT_SIZE_NONE;
    }
}
