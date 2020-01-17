#include <unistd.h>
#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

int 	g_File 		= 0;
void 	*g_pData 	= NULL;

void * Map(char* szFileName)
{
	g_File = open(szFileName, O_RDWR);  
	if (g_File < 0)   
	{   
		g_File = 0;  
		return NULL;   
	}  
	struct stat status;  
	fstat(g_File, &status);  

	g_pData = mmap(0, status.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, g_File, 0);  
	if (MAP_FAILED != g_pData) {
		return g_pData;
	}  

	close(g_File);  
	g_pData = NULL;  
	g_File = 0;  
	return NULL;  
}

void displayEhdr(Elf32_Ehdr *ehdr)
{
	printf("Magic:");
	int i = 0;
	for(i = 0; i < EI_NIDENT;i++){
		printf(" %02x",ehdr->e_ident[i]);
	}
	printf("\n");
	printf("Version:			0x%x\n",ehdr->e_version);
	printf("Entry point address:		0x%x\n",ehdr->e_entry);
	printf("Start of program headers:	%d (bytes into file)\n",ehdr->e_phoff);
	printf("Start of section headers:	%d (bytes into file)\n",ehdr->e_shoff);
	printf("Flags:				%d\n",ehdr->e_flags);
	printf("Size of this header:		%d (bytes)\n",ehdr->e_ehsize);
	printf("Size of program headers:	%d (bytes)\n",ehdr->e_phentsize);
	printf("Number of program headers:	%d\n",ehdr->e_phnum);
	printf("Size of section headers:	%d (bytes)\n",ehdr->e_shentsize);
	printf("Number of section headers:	%d\n",ehdr->e_shnum);
	printf("Section header string table index:	%d\n",ehdr->e_shstrndx);
}

int main(int argc,char *argv[])
{
	if(argc != 2){
		printf("parameter error\n");
		exit(0);
	}
	Elf32_Ehdr *ehdr = (Elf32_Ehdr *)Map(argv[1]);
	if(ehdr == NULL){
		perror("Map Error\n");
		exit(0);
	}
	displayEhdr(ehdr);
}
