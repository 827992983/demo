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
    LOG_DEBUG("File %s Size:%d", path, fileSize);
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

void PrintNTHeaders(const char *path)
{
    int ret = 0;
    unsigned int size = 0;
    unsigned char *pFileBuffer = NULL;
    PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_NT_HEADERS pNTHeader = NULL;
    PIMAGE_FILE_HEADER pPEHeader = NULL;
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;

    ret = LoadFile(path, &pFileBuffer, &size);
    if(ret<0)
    {
        LOG_DEBUG("LoadFile Error");
        return ;
    }

    pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
    //判断是否是有效的MZ标志
    if(CheckDosHeaderMagic(pDosHeader->e_magic) < 0)
    {
        free(pFileBuffer);
        return ;
    }
    //打印DOC头
    LOG_DEBUG("********************DOC头********************");
    LOG_DEBUG("MZ标志：%x",pDosHeader->e_magic);
    LOG_DEBUG("PE偏移：%x",pDosHeader->e_lfanew);
    //判断是否是有效的PE标志
    if(*((PDWORD)((DWORD)pFileBuffer+pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
    {
        LOG_DEBUG("不是有效的PE标志");
        free(pFileBuffer);
        return ;
    }
    pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer+pDosHeader->e_lfanew);
    //打印NT头
    LOG_DEBUG("********************NT头********************");
    LOG_DEBUG("NT：%x\n",pNTHeader->Signature);
    pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
    LOG_DEBUG("********************PE头********************");
    LOG_DEBUG("PE：%x",pPEHeader->Machine);
    LOG_DEBUG("节的数量：%x",pPEHeader->NumberOfSections);
    LOG_DEBUG("SizeOfOptionalHeader：%x",pPEHeader->SizeOfOptionalHeader);
    //可选PE头
    pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader+IMAGE_SIZEOF_FILE_HEADER);
    LOG_DEBUG("********************OPTIOIN_PE头********************");
    LOG_DEBUG("OPTION_PE：%x",pOptionHeader->Magic);
    //释放内存
    free(pFileBuffer);
}


