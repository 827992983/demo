/***********************************************************************/
/*	AUTHOR	:	FangJianYang											
/*	VERSION	:	01														
/*	TIME	:	2019-02-17												
/*	DESC	:	Some function to read a elf file						
/*	Email	:	fangjianyang_main@163.com								
/************************************************************************/
#include "readelf.h"
#include <stdio.h>
#include <stdlib.h>
CReadElf::CReadElf(char *argc):osType(0),filename(""),pFile(NULL)
{
	if (argc!=NULL && strlen(argc) != 0)
	{
		filename= argc;
	}
}

CReadElf::~CReadElf()
{
	if(pFile != NULL)
		fclose(pFile);
}

int CReadElf::readFile()
{
	long lSize;
	size_t result;

	// obtain file size:
	fseek (pFile , 0 , SEEK_END);
	lSize = ftell (pFile);
	rewind (pFile);

	if(lSize < sizeof(Elf32_Ehdr) || lSize < sizeof(Elf64_Ehdr) )
	{
		cout<<"not a elf file!"<<endl;
		return NOT_A_ELF_FILE;
	}


	char headbuf[EI_NIDENT] = {0};
	result = fread(headbuf,1,EI_NIDENT,pFile);

	//judge if this is a elf file
	if(
		headbuf[0] != 0x7f && headbuf[1] != 0x45 &&
		headbuf[2] != 0x4c && headbuf[3] != 0x46
		)    
	{
		cout<<"not a elf file!"<<endl;
		return NOT_A_ELF_FILE;
	}

	rewind(pFile);
	if(headbuf[4] == 0x02)
	{
		fread (&elfHead64,1,sizeof(Elf64_Ehdr),pFile);
		osType = 64;
	}
	else
	{
		fread (&elfHead32,1,sizeof(Elf32_Ehdr),pFile);
		osType = 32;
	}
	//cout<<osType<<endl;
	rewind(pFile);
	return SUCCESS;
}


int CReadElf::readSection()
{
	size_t result;
	if(osType == 64)
	{
		size_t secNum = elfHead64.e_shnum;
		int secindex = elfHead64.e_shoff;


		if(getSectionName()!= secNum)
		{
			cout<<"get section head failed"<<endl;
			return GET_SEC_NAME_ERR;
		}
		//go to the entry of section
		fseek(pFile,secindex,SEEK_SET);

		Elf64_Shdr elf64Sec;
		
		for(int i = 0;i < secNum;i++)
		{
			result = fread(&elf64Sec,1,sizeof(Elf64_Shdr),pFile); 
			if(result != sizeof(Elf64_Shdr))
			{
				cout<<"read file failed"<<endl;
				return READ_FILE_FAILED;
			}
			myElf64_Shdr tmpsec;
			tmpsec.sh_strname = secName[i];
			tmpsec.elf64sehd = elf64Sec;
			sections.push_back(tmpsec);   
		}
	}
	else
	{
		size_t secNum = elfHead32.e_shnum;
		int secindex = elfHead32.e_shoff;

		if(getSectionName()!= secNum)
		{
			cout<<"get section head failed"<<endl;
			return GET_SEC_NAME_ERR;
		}
		//go to the entry of section
		fseek(pFile,secindex,SEEK_SET);

		Elf32_Shdr elf32Sec;
		
		for(int i = 0;i < secNum;i++)
		{
			result = fread(&elf32Sec,1,sizeof(Elf32_Shdr),pFile); 
			if(result != sizeof(Elf32_Shdr))
			{
				cout<<"read file failed"<<endl;
				return READ_FILE_FAILED;
			}
			myElf32_Shdr tmpsec;
			tmpsec.sh_strname = secName[i];
			tmpsec.elf32sehd = elf32Sec;
			sections32.push_back(tmpsec);   
		}
	}
	rewind(pFile);
	return SUCCESS;  
}


int CReadElf::getfd()
{
	pFile = fopen (filename.c_str() , "rb" );
	if (pFile==NULL) 
	{
		cout<<"File error"<<endl;
		return FILE_OPEN_ERR;
	}
	return SUCCESS;
}

int CReadElf::getSectionName()
{
	if (osType == 64)
	{
		Elf64_Shdr *shdr = new Elf64_Shdr[sizeof(Elf64_Shdr) * elfHead64.e_shnum];

		int sz = fseek(pFile, elfHead64.e_shoff, SEEK_SET);
		if (sz != 0)
		{
			printf("file fseek ERROR\n");
			delete[] shdr;
			return FILE_SEEK_ERROR;
		}
		sz = fread(shdr, sizeof(Elf64_Shdr) * elfHead64.e_shnum, 1, pFile);
		//if(sz != sizeof(Elf64_Shdr) * elfHead64.e_shnum)
		if (sz == 0)
		{
			printf("file read ERROR \n");
			delete[] shdr;
			return READ_FILE_FAILED;
		}
		rewind(pFile);

		sz = fseek(pFile, shdr[elfHead64.e_shstrndx].sh_offset, SEEK_SET);
		if (sz != 0)
		{
			printf("file fseek ERROR\n");
			delete[] shdr;
			return FILE_SEEK_ERROR;
		}
		char shstrtab[shdr[elfHead64.e_shstrndx].sh_size];
		char *temp = NULL;
		sz = fread(shstrtab, shdr[elfHead64.e_shstrndx].sh_size, 1, pFile);
		if (sz == 0)
		{
			printf("file fread ERROR\n");
			delete[] shdr;
			return FILE_SEEK_ERROR;
		}
		for (int shnum = 0; shnum < elfHead64.e_shnum; shnum++)
		{
			temp = shstrtab;
			temp = temp + shdr[shnum].sh_name;
			secName.push_back(string(temp));
		}
		delete[] shdr;
	}
	else
	{
		Elf32_Shdr *shdr = new Elf32_Shdr[sizeof(Elf32_Shdr) * elfHead32.e_shnum];

		int sz = fseek(pFile, elfHead32.e_shoff, SEEK_SET);
		if (sz != 0)
		{
			printf("file fseek ERROR\n");
			delete[] shdr;
			return FILE_SEEK_ERROR;
		}
		sz = fread(shdr, sizeof(Elf32_Shdr) * elfHead32.e_shnum, 1, pFile);
		if (sz == 0)
		{
			printf("file read ERROR \n");
			delete[] shdr;
			return READ_FILE_FAILED;
		}
		rewind(pFile);
		sz = fseek(pFile, shdr[elfHead32.e_shstrndx].sh_offset, SEEK_SET);
		if (sz != 0)
		{
			printf("file fseek ERROR\n");
			delete[] shdr;
			return FILE_SEEK_ERROR;
		}
		char shstrtab[shdr[elfHead32.e_shstrndx].sh_size];
		char *temp = NULL;
		sz = fread(shstrtab, shdr[elfHead32.e_shstrndx].sh_size, 1, pFile);
		if (sz == 0)
		{
			printf("file fread ERROR\n");
			delete[] shdr;
			return FILE_SEEK_ERROR;
		}
		for (int shnum = 0; shnum < elfHead32.e_shnum; shnum++)
		{
			temp = shstrtab;
			temp = temp + shdr[shnum].sh_name;
			secName.push_back(string(temp));
		}
		delete[] shdr;
	}
	rewind(pFile);
	return secName.size();	
}


int CReadElf::readSegment()
{
	if (osType == 64)
	{
		int phoffset = elfHead64.e_phoff;
		int phnum = elfHead64.e_phnum;
		int phentsize = elfHead64.e_phentsize;

		fseek(pFile, phoffset, SEEK_SET);
		for (int i = 0; i < phnum; i++)
		{
			Elf64_Phdr Pro_header;
			if (fread(&Pro_header, 1, phentsize, pFile) != phentsize)
			{
				cout << "read segments err!" << endl;
				return READ_FILE_FAILED;
			}
			segments.push_back(Pro_header);
		}
	}
	else
	{
		int phoffset = elfHead32.e_phoff;
		int phnum = elfHead32.e_phnum;
		int phentsize = elfHead32.e_phentsize;

		fseek(pFile, phoffset, SEEK_SET);
		for (int i = 0; i < phnum; i++)
		{
			Elf32_Phdr Pro_header;
			if (fread(&Pro_header, 1, phentsize, pFile) != phentsize)
			{
				cout << "read segments err!" << endl;
				return READ_FILE_FAILED;
			}
			segments32.push_back(Pro_header);
		}
	}
	return SUCCESS;
}

/**********************************section to Segment mapping  计算方法:***************************
 首先,查看program Headers中的各个字段的地址 virtAddr (或 physAddr 一般这两个字段的值是一样的).         
 表示这个*segment的开始地址,然后看MenSiz(注意,不是FileSize).表示这个segment可以组装的section的大小.    
 我们对上面两个值相加,获得这个segment的开始地址和结束地址.比如LOADsegment:                       
 开始地址为: 0x0000000000400000,结束地址为 0x00000000004007dc.                                   
 然后明确: elf会将地址连续的section分配到同一个segment,前提是这些section的地址在某个segment的范围内.    
 比如说:Section Headers 字段中,分布在地址 0x0000000000400000 - 0x00000000004007dc                
 刚好是 "interp .note.ABI-tag .note.gnu.build*id .gnu.hash .dynsym                            
.dynstr .gnu.version .gnu.version_r .rela.dyn .rela.plt .init .plt                           
.text .fini .rodata .eh_frame_hdr .eh_frame"                                                 
 其中过最后一个section的开始地址为 4006e8 大小为 f4 相加后刚好为:4007DC.                            
***********************************************************************************************/
int CReadElf::caclSec2Segments()
{
	if (osType == 64)
	{
		if (sections.size() == 0 || segments.size() == 0)
		{
			cout << "can not cal sectiong to segments mapping" << endl;
			return CALC_MAPPING_ERROR;
		}

		for (vector<Elf64_Phdr>::iterator pit = segments.begin(); pit != segments.end(); pit++)
		{
			string belongSec("");

			Elf64_Addr startAddr = pit->p_paddr;
			Elf64_Addr endAddr = pit->p_paddr + pit->p_memsz;
			for (vector<myElf64_Shdr>::iterator sit = sections.begin(); sit != sections.end(); sit++)
			{
				Elf64_Addr secBeginAddr = sit->elf64sehd.sh_addr;
				Elf64_Addr secEndAddr = sit->elf64sehd.sh_addr + sit->elf64sehd.sh_size;
				if (secBeginAddr >= startAddr && secEndAddr <= endAddr)
				{
					belongSec.append(sit->sh_strname);
					belongSec.append(" ");
				}
			}
			sec2SegMapping tmpmap(mapping.size(), belongSec);
			mapping.push_back(tmpmap);
		}
	}
	else
	{
		if (sections32.size() == 0 || segments32.size() == 0)
		{
			cout << "can not cal sectiong to segments mapping" << endl;
			return CALC_MAPPING_ERROR;
		}

		for (vector<Elf32_Phdr>::iterator pit = segments32.begin(); pit != segments32.end(); pit++)
		{
			string belongSec("");

			Elf32_Addr startAddr = pit->p_paddr;
			Elf32_Addr endAddr = pit->p_paddr + pit->p_memsz;
			for (vector<myElf32_Shdr>::iterator sit = sections32.begin(); sit != sections32.end(); sit++)
			{
				Elf32_Addr secBeginAddr = sit->elf32sehd.sh_addr;
				Elf32_Addr secEndAddr = sit->elf32sehd.sh_addr + sit->elf32sehd.sh_size;
				if (secBeginAddr >= startAddr && secEndAddr <= endAddr)
				{
					belongSec.append(sit->sh_strname);
					belongSec.append(" ");
				}
			}
			sec2SegMapping tmpmap(mapping.size(), belongSec);
			mapping.push_back(tmpmap);
		}
	}
	return SUCCESS;	
}

void CReadElf::showHead()
{
	if (osType == 64)
	{
		printf("e_type		 : %x \n", elfHead64.e_type);
		printf("e_machine	 : %x \n", elfHead64.e_machine);
		printf("e_version	 : %x \n", elfHead64.e_version);
		printf("e_entry		 : %x \n", elfHead64.e_entry);
		printf("e_phoff		 : %x \n", elfHead64.e_phoff);
		printf("e_shoff		 : %x \n", elfHead64.e_shoff);
		printf("e_flags		 : %x \n", elfHead64.e_flags);
		printf("e_ehsize	 : %x \n", elfHead64.e_ehsize);
		printf("e_phentsize	 : %x \n", elfHead64.e_phentsize);
		printf("e_phnum		 : %x \n", elfHead64.e_phnum);
		printf("e_shentsize	 : %x \n", elfHead64.e_shentsize);
		printf("e_shnum		 : %x \n", elfHead64.e_shnum);
		printf("e_shstrndx	 : %x \n", elfHead64.e_shstrndx);
	}
	else
	{
		printf("e_type		 : %x \n", elfHead32.e_type);
		printf("e_machine	 : %x \n", elfHead32.e_machine);
		printf("e_version	 : %x \n", elfHead32.e_version);
		printf("e_entry		 : %x \n", elfHead32.e_entry);
		printf("e_phoff		 : %x \n", elfHead32.e_phoff);
		printf("e_shoff		 : %x \n", elfHead32.e_shoff);
		printf("e_flags		 : %x \n", elfHead32.e_flags);
		printf("e_ehsize	 : %x \n", elfHead32.e_ehsize);
		printf("e_phentsize	 : %x \n", elfHead32.e_phentsize);
		printf("e_phnum		 : %x \n", elfHead32.e_phnum);
		printf("e_shentsize	 : %x \n", elfHead32.e_shentsize);
		printf("e_shnum		 : %x \n", elfHead32.e_shnum);
		printf("e_shstrndx	 : %x \n", elfHead32.e_shstrndx);
	}
	printf("\n\n");
}

void CReadElf::showSection()
{
	if (osType == 64)
	{
		if (sections.size() == 0)
		{
			cout << "empty section map" << endl;
			return;
		}
		printf("%-20s %-8s %-16s %-8s %-16s %-16s %-8s %-8s %-8s %-8s\n",
			   "Name", "Type", "Address", "Offset", "Size", "EntSize", "Flags", "Link", "Info", "Align");
		for (vector<myElf64_Shdr>::iterator pit = sections.begin(); pit != sections.end(); pit++)
		{
			printf("%-20s %-8x %016x %08x %016x %016x %-8x %-8x %-8x %-8x\n",
				   pit->sh_strname.c_str(),
				   pit->elf64sehd.sh_type,
				   pit->elf64sehd.sh_addr,
				   pit->elf64sehd.sh_offset,
				   pit->elf64sehd.sh_size,
				   pit->elf64sehd.sh_entsize,
				   pit->elf64sehd.sh_flags,
				   pit->elf64sehd.sh_link,
				   pit->elf64sehd.sh_info,
				   pit->elf64sehd.sh_addralign
			);
		}
	}
	else
	{
		if (sections32.size() == 0)
		{
			cout << "empty section map" << endl;
			return;
		}
		printf("%-20s %-8s %-16s %-8s %-16s %-16s %-8s %-8s %-8s %-8s\n",
			   "Name", "Type", "Address", "Offset", "Size", "EntSize", "Flags", "Link", "Info", "Align");
		for (vector<myElf32_Shdr>::iterator pit = sections32.begin(); pit != sections32.end(); pit++)
		{
			printf("%-20s %-8x %016x %08x %016x %016x %-8x %-8x %-8x %-8x\n",
				   pit->sh_strname.c_str(),
				   pit->elf32sehd.sh_type,
				   pit->elf32sehd.sh_addr,
				   pit->elf32sehd.sh_offset,
				   pit->elf32sehd.sh_size,
				   pit->elf32sehd.sh_entsize,
				   pit->elf32sehd.sh_flags,
				   pit->elf32sehd.sh_link,
				   pit->elf32sehd.sh_info,
				   pit->elf32sehd.sh_addralign
			);
		}
	}

	printf("\n\n");
}

void CReadElf::showSegments()
{
	if (osType == 64)
	{
		if (segments.size() == 0)
		{
			cout << "segments reads err!" << endl;
			return;
		}
		printf("%-12s %-18s %-18s %-18s %-18s %-18s %-8s %-8s\n",
			   "Type", "Offset", "VirtAddr", "PhysAddr", "FileSiz", "MemSiz", "Flags", "Align");
		for (vector<Elf64_Phdr>::iterator pit = segments.begin(); pit != segments.end(); pit++)
		{
			printf("%-12x 0x%016x 0x%016x 0x%016x 0x%016x 0x%016x %-8x %-8x\n",
				   pit->p_type,
				   pit->p_offset,
				   pit->p_vaddr,
				   pit->p_paddr,
				   pit->p_filesz,
				   pit->p_memsz,
				   pit->p_flags,
				   pit->p_align
			);
		}
	}
	else
	{
		if (segments32.size() == 0)
		{
			cout << "segments reads err!" << endl;
			return;
		}
		printf("%-12s %-18s %-18s %-18s %-18s %-18s %-8s %-8s\n",
			   "Type", "Offset", "VirtAddr", "PhysAddr", "FileSiz", "MemSiz", "Flags", "Align");
		for (vector<Elf32_Phdr>::iterator pit = segments32.begin(); pit != segments32.end(); pit++)
		{
			printf("%-12x 0x%016x 0x%016x 0x%016x 0x%016x 0x%016x %-8x %-8x\n",
				   pit->p_type,
				   pit->p_offset,
				   pit->p_vaddr,
				   pit->p_paddr,
				   pit->p_filesz,
				   pit->p_memsz,
				   pit->p_flags,
				   pit->p_align
			);
		}		
	}
	printf("\n\n");
	
}


void CReadElf::showSec2SegMapping()
{
	if(mapping.size() == 0)
	{
		cout<<"mapping error"<<endl;
		return;
	}
	for(vector<sec2SegMapping>::iterator pit = mapping.begin();pit != mapping.end();pit++)
	{
		cout<< pit->index <<'\t'<<pit->secNameVec<<endl;
	}
	cout<<endl;
}
