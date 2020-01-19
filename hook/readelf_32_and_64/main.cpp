/************************************************************************/
/*	AUTHOR	:	FangJianYang											
/*	VERSION	:	01														
/*	TIME	:	2019-02-17												
/*	DESC	:	Some function to read a elf file						
/*	Email	:	fangjianyang_main@163.com								
/************************************************************************/

#include "readelf.h"

int main(int argc,char** argv)
{
	if(argc != 2)
	{
		cout<<"argments err : you should enter 2 argments!"<<endl;
		return WRONG_ARGMENTS;
	}

	CReadElf obj(argv[1]);
	int rt = obj.getfd();
	if(rt != SUCCESS)
	{
		return rt;
	}

	rt = obj.readFile();
	if(rt != SUCCESS)
	{
		return rt;
	}

	cout<<"ELF head infomation"<<endl;
	obj.showHead();


	cout<<"section infomation"<<endl;
	rt = obj.readSection();
	if(rt != SUCCESS)
	{
		return rt;
	}
	obj.showSection();

	cout<<"segment infomation"<<endl;
	rt = obj.readSegment();
	if(rt != SUCCESS)
	{
		return rt;
	}
	obj.showSegments();

	rt = obj.caclSec2Segments();
	if(rt != SUCCESS)
	{
		return rt;
	}	

	cout<<"section to segment mapping"<<endl;
	obj.showSec2SegMapping();

	return 0;
}
