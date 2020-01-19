/************************************************************************/
/*	AUTHOR	:	FangJianYang											
/*	VERSION	:	01														
/*	TIME	:	2019-02-17												
/*	DESC	:	Some function to read a elf file						
/*	Email	:	fangjianyang_main@163.com								
/************************************************************************/
#include <elf.h>
#include <iostream>
#include <string.h>
#include <vector>
#include <map>
#include <string>
using namespace std;


#define SUCCESS				0
#define WRONG_ARGMENTS		-1
#define FILE_OPEN_ERR		-2
#define NOT_A_ELF_FILE		-3
#define READ_FILE_FAILED	-4
#define FILE_SEEK_ERROR		-5
#define GET_SEC_NAME_ERR	-6
#define CALC_MAPPING_ERROR	-7


typedef struct
{
	string 		sh_strname;
	Elf64_Shdr 	elf64sehd;
}myElf64_Shdr;

typedef struct
{
	string 		sh_strname;
	Elf32_Shdr 	elf32sehd;
}myElf32_Shdr;

typedef struct  sec2SegMapping
{
	int index;
	string secNameVec;
public:
	sec2SegMapping(int id,string arg):index(id),secNameVec(arg){}
}sec2SegMapping;

class CReadElf
{
private:
	int osType ;
	vector<string> secName;
	FILE * pFile;
	string filename;
	vector<sec2SegMapping> mapping;

private:	
	vector<myElf64_Shdr> sections;
	vector<Elf64_Phdr> segments;	
	Elf64_Ehdr elfHead64;

private:
	vector<myElf32_Shdr> sections32;
	vector<Elf32_Phdr> segments32;
	Elf32_Ehdr elfHead32;
	
public:
	CReadElf(char *argc);
	virtual ~CReadElf();
	int getfd();

public:
	int readFile();
	int readSection();
	int readSegment();
	int getSectionName();
	int caclSec2Segments();
	

	void showHead();
	void showSection();
	void showSegments();
	void showSec2SegMapping();
};


