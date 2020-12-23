/**
PE文件（Portable File）是Windows平台portable File Format（可移植文件）的简写。常见的PE文件有：exe,sys,dll等。了解PE文件格式有助于加深对操作系统的理解，掌握可执行文件的数据结构机器运行机制，对于逆向破解，加壳等安全方面方面的同学极其重要
*/

/*
说明：
1.由于PE文件结构特别多，加*的内容需要重点掌握
2.理解RVA和FOA如何转化，这个对于PE文件解析非常重要
3.一定要手动操作，写代码解析，否则不可能真正掌握PE
*/

/*
PE文件组成：DOS头，NT头（PE标识+PE头+可选PE头），节表，节，资源等等。
*/
//1.DOS头
struct _IMAGE_DOS_HEADER {
    WORD e_magic;// 5a 4d * #MZ，dos头的幻数
    WORD e_cblp;//00 90
    WORD e_cp;//00 03 
    WORD e_crlc;//00 00
    WORD e_cparhdr;//00 04
    WORD e_minalloc;//00 00
    WORD e_maxalloc;//ff ff
    WORD e_ss;//00 00
    WORD e_sp;//00 b8
    WORD e_csum;//00 00
    WORD e_ip;//00 00
    WORD e_cs;//00 00
    WORD e_lfarlc;//00 40
    WORD e_ovno;//00 00
    WORD e_res[4];//00 00 00 00 00 00 00 00
    WORD e_oemid;//00 00
    WORD e_oeminfo;//00 00
    WORD e_res2[10];//00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
    DWORD e_lfanew;//00 00 00 f8 * #PE头相对于文件的偏移，用于定位PE文件（具体值会由于编译器不同，具体值不一定）
};

//2.NT头
struct _IMAGE_NT_HEADERS {
    DWORD Signature;//00 00 45 50 
    _IMAGE_FILE_HEADER FileHeader;
    _IMAGE_OPTIONAL_HEADER OptionalHeader;
};
//2.1标准PE头
struct _IMAGE_FILE_HEADER {
    WORD Machine;//01 4c * #程序运行的CPU型号：0x0 任何处理器/0x14C 386及后续处理器
    WORD NumberOfSections;//00 06 * #节（Section）数，PE文件时候分节的，即：PE文件中存在的节的总数,如果要新增节或者合并节 就要修改这个值.
    DWORD TimeDateStamp;//5f d2 c6 a7 * #时间戳：文件的创建时间(和操作系统的创建时间无关)，编译器填写的.
    DWORD PointerToSymbolTable;//00 00 00 00 #
    DWORD NumberOfSymbols;//00 00 00 00 #
    WORD SizeOfOptionalHeader;//00 e0 * #可选PE头的大小，32位PE文件默认E0h 64位PE文件默认为F0h  大小可以自定义.
    WORD Characteristics;//01 02 * #每个位有不同的含义，可执行文件值为10F 即0 1 2 3 8位置1 
};
//2.2可选PE头（大小不确定）
struct _IMAGE_OPTIONAL_HEADER {
    WORD Magic;//01 0b * #说明文件类型：10B 32位下的PE文件     20B 64位下的PE文件
    BYTE MajorLinkerVersion;//0e #
    BYTE MinorLinkerVersion;//00 #
    DWORD SizeOfCode;//00 00 0c 00 * #所有代码节的和，必须是FileAlignment的整数倍 编译器填的  没用
    DWORD SizeOfInitializedData;//00 00 16 00* #已初始化数据大小的和,必须是FileAlignment的整数倍 编译器填的  没用
    DWORD SizeOfUninitializedData;//00 00 00 00 * #未初始化数据大小的和,必须是FileAlignment的整数倍 编译器填的  没用
    DWORD AddressOfEntryPoint;//00 00 12 57 * #程序入口，ImageBase+AddressOfEntryPoint才是真正的程序入口
    DWORD BaseOfCode;//00 00 10 00 * #代码开始的基址，编译器填的   没用
    DWORD BaseOfData;//00 00 20 00 * #数据开始的基址，编译器填的   没用
    DWORD ImageBase;//00 40 00 00 * #内存镜像基址，ImageBase+AddressOfEntryPoint才是真正的程序入口
    DWORD SectionAlignment;//00 00 10 00 * #内存对齐
    DWORD FileAlignment;//00 00 02 00 * #文件对齐
    WORD MajorOperatingSystemVersion;//00 06 #
    WORD MinorOperatingSystemVersion;//00 00 #
    WORD MajorImageVersion;//00 00 #
    WORD MinorImageVersion;//00 00 #
    WORD MajorSubsystemVersion;//00 06 #
    WORD MinorSubsystemVersion;//00 00 #
    DWORD Win32VersionValue;//00 00 00 00 #
    DWORD SizeOfImage;//00 00 70 00 * #内存中整个PE文件的映射的尺寸（已经按内存对齐后的大小），可以比实际的值大，但必须是SectionAlignment的整数倍
    DWORD SizeOfHeaders;//00 00 04 00 * #所有头+节表按照文件对齐后的大小，否则加载会出错
    DWORD CheckSum;//00 00 00 00 * #校验和，一些系统文件有要求.用来判断文件是否被修改.
    WORD Subsystem;//00 03 #
    WORD DllCharacteristics;//81 40 #
    DWORD SizeOfStackReserve;//00 10 00 00 * #初始化时保留的堆栈大小 
    DWORD SizeOfStackCommit;//00 00 10 00 * #初始化时实际提交的大小 
    DWORD SizeOfHeapReserve;//00 10 00 00 * #初始化时保留的堆大小 
    DWORD SizeOfHeapCommit;//00 10 00 00 * #初始化时实践提交的大小 
    DWORD LoaderFlags;//00 00 00 00 #
    DWORD NumberOfRvaAndSizes;//00 00 00 10 #目录项数目
    _IMAGE_DATA_DIRECTORY DataDirectory[16];// #
};

//3.节表（距离文件起始偏移位置：DOS头+PE头+可选PE头）
/*
节表个数：通过标准PE头（_IMAGE_FILE_HEADER）的NumberOfSections字段决定的
*/
#define IMAGE_SIZEOF_SHORT_NAME 8
typedef struct _IMAGE_SECTION_HEADER {
    BYTE Name[IMAGE_SIZEOF_SHORT_NAME]; //名称,长度:8位(16字节)的ASCII码 .text .data
	union {
 	    DWORD PhysicalAddress;
     	DWORD VirtualSize;
	} Misc;//V(VS),内存中大小(对齐前的长度)，该节在没有对齐之前的真实长度（实际数据大小，对齐解释：如以0x200大小对齐，0x192就会通过补0变成0x200），这个值可能不准确（可能被别人修改）
    DWORD VirtualAddress;//V(VO),内存中偏移(该块的RVA)，VirtualAddress 在内存中的偏移 相对于ImageBase偏移(简单理解：离ImageBase多远），在内存中有意义
    DWORD SizeOfRawData;//R(RS),文件中大小(对齐后的长度)，节在文件中对齐后的大小
    DWORD PointerToRawData;//R(RO),文件中偏移.节区在文件中的偏移（对齐后），在文件中
    DWORD PointerToRelocations;//在OBJ文件中使用,重定位的偏移.在OBJ文件中使用,重定位的偏移.在obj文件中使用 对exe无意义
    DWORD PointerToLinenumbers;//行号表的偏移,提供调试.行号表的位置 调试的时候使用
    WORD NumberOfRelocations;//在obj文件中使用 重定位项数目 对exe无意义
    WORD NumberOfLinenumbers;//行号表中行号的数量 调试的时候使用
    DWORD Characteristics;//节的属性
};
//区别：VirtualAddress（内存中）和PointerToRawData（文件中）

//RVA:相对偏移地址，或叫相对虚拟地址，可以理解为文件被装载到虚拟内存(拉伸)后先对于基址的偏移地址。
//FOA:文件偏移地址，可以理解为文件在磁盘上存放时相对于文件开头的偏移地址。
//RVA = VA(虚拟地址) - ImageBase(基址)

//4.导出表
typedef struct _IMAGE_EXPORT_DIRECTORY {									
    DWORD   Characteristics;				// 未使用					
    DWORD   TimeDateStamp;				    // 时间戳					
    WORD    MajorVersion;				    // 未使用					 
    WORD    MinorVersion;				    // 未使用					 
    DWORD   Name;				            // *指向该导出表文件名字符串 
    DWORD   Base;				            // *导出函数起始序号		 
    DWORD   NumberOfFunctions;				// *所有导出函数的个数		 
    DWORD   NumberOfNames;				    // *以函数名字导出的函数个数					
    DWORD   AddressOfFunctions;             // *导出函数地址表RVA									
    DWORD   AddressOfNames;                 // *导出函数名称表RVA									
    DWORD   AddressOfNameOrdinals;          // *导出函数序号表RVA									
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;									

//5.重定位表
//在程序加载时候，尤其是DLL，可能ImageBase都是重复的，那么加载时候，就有可能加载不成功，所以需要换个新地址作为ImageBase加载，但是这样就导致很多数据都需要修改地址，这就是重定位表的意义。
typedef struct _IMAGE_BASE_RELOCATION {
    DWORD VirtualAddress; //要修改的地址的基地址(RVA)
    DWORD SizeOfBlock; //当前整个块大小(包含IMAGE_BASE_RELOCATION结构体和他后面的部分，直到下一个IMAGE_BASE_RELOCATION结构体之前）
} IMAGE_BASE_RELOCATION;
typedef IMAGE_BASE_RELOCATION UNALIGNED *PIMAGE_BASE_RELOCATION;
//解释一下这个结构，这个结构有8字节，在8字节后面是SizeOfBlock-8字节，后面的内容按2次节对齐，VirtualAddress+WORD值的低12位（高4位是0x3的时候，才需要修改地址）：代表真正要修改的地址
//一般内存按0x1000对齐，也就是一页中的内存
//到什么时候这个这些IMAGE_BASE_RELOCATION结束呢？答：全0的时候，VirtualAddress=0，SizeOfBlock=0
//多少个需要判断的项：(SizeOfBlock-8)/2 个，然后再判断高4位，确定是否需要修改

//6.导入表
typedef struct _IMAGE_IMPORT_DESCRIPTOR {									
    union {									
        DWORD   Characteristics;           									
        DWORD   OriginalFirstThunk;      //* 用这个，RVA 指向IMAGE_THUNK_DATA结构数组			
    };									
    DWORD   TimeDateStamp;               //* 时间戳		值为0：表示IAT表还没绑定， 值为FFFFFFFF：表示IAT表被绑定（程序启动快）	
    DWORD   ForwarderChain;              									
    DWORD   Name;						 //RVA,指向dll名字，该名字已0结尾			
    DWORD   FirstThunk;                  //* RVA,指向IMAGE_THUNK_DATA结构数组			
} IMAGE_IMPORT_DESCRIPTOR;									
typedef IMAGE_IMPORT_DESCRIPTOR UNALIGNED *PIMAGE_IMPORT_DESCRIPTOR;
									
typedef struct _IMAGE_THUNK_DATA32 {												
    union {												
        PBYTE  ForwarderString;												
        PDWORD Function;												
        DWORD Ordinal;						       //序号						
        PIMAGE_IMPORT_BY_NAME  AddressOfData;	   //*指向IMAGE_IMPORT_BY_NAME						
    } u1;												
} IMAGE_THUNK_DATA32;												
typedef IMAGE_THUNK_DATA32 * PIMAGE_THUNK_DATA32;												
												
												
typedef struct _IMAGE_IMPORT_BY_NAME {												
    WORD    Hint;						           //可能为空，编译器决定 如果不为空 是函数在导出表中的索引						
    BYTE    Name[1];						       //*函数名称，以0结尾						
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;												

//7.绑定导入表
/*
PE加载EXE相关的DLL时，首先会根据IMAGE_IMPORT_DESCRIPTOR结构中的TimeDateStamp来判断是否要重新计算IAT表中的地址。                                    
    TimeDateStamp == 0  未绑定                                    
    TimeDateStamp == -1 已绑定 真正的绑定时间为IMAGE_BOUND_IMPORT_DESCRIPTOR的TimeDateStamp      

有些应用程序，如：windows的notepad.exe,为了启动快，把DLL中函数地址直接绑定到exe文件中，这就是绑定导入表。
好处：启动快，但是如果DLL改动，还是需要重定位
*/
typedef struct _IMAGE_BOUND_IMPORT_DESCRIPTOR {								
    DWORD   TimeDateStamp;						  //*真正的时间戳,	用来判断是否和绑定的dll是同一个版本；也就是看时间戳和dll的pe头中的时间戳是否一样；
    WORD    OffsetModuleName;					  //*DLL的名字. PE的文件名	
    WORD    NumberOfModuleForwarderRefs;		  //*依赖的另外的DLL有几个					
// Array of zero or more IMAGE_BOUND_FORWARDER_REF follows								
} IMAGE_BOUND_IMPORT_DESCRIPTOR,  *PIMAGE_BOUND_IMPORT_DESCRIPTOR;								
								
typedef struct _IMAGE_BOUND_FORWARDER_REF {								
    DWORD   TimeDateStamp;					//*时间戳		
    WORD    OffsetModuleName;				//*成员.这个成员不是RVA 也不是FOA 而是第一个绑定导入表地址 + 这个成员的值，才是一个指针，这个指针才是真正的文件名所在的位置.不管你打印到第几个 永远都是 第一个绑定导入表的值 + OffsetModuleName的值		
    WORD    Reserved;						//保留，无用		
} IMAGE_BOUND_FORWARDER_REF, *PIMAGE_BOUND_FORWARDER_REF;								
//当IMAGE_BOUND_IMPORT_DESCRIPTOR结构中的TimeDateStamp与DLL文件标准PE头中的TimeDateStamp值不相符时，或者DLL需要重新定位的时候，就会重新计算IAT中的值.

//8.资源表
/*
资源表是PE文件最复杂的表，共分三级
说明：资源表相关数据都是UNICODE
*/
/*
8.1资源目录（从可选PE头RVA to FOA过来）
*/			
typedef struct _IMAGE_RESOURCE_DIRECTORY {								
    DWORD   Characteristics;						//资源属性  保留 0		
    DWORD   TimeDateStamp;						    //资源创建的时间		
    WORD    MajorVersion;						    //资源版本号 未使用 0		
    WORD    MinorVersion;						    //资源版本号 未使用 0		
    WORD    NumberOfNamedEntries;				    //*以名称命名的资源数量		
    WORD    NumberOfIdEntries;						//*以ID命名的资源数量		
//  IMAGE_RESOURCE_DIRECTORY_ENTRY DirectoryEntries[];								
} IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;	 							

/*
8.2资源目录项（第一级，紧挨着资源目录，资源类型：光标（1）， 位图（2），图标（3）共16种）
最高位如果为1：低31位 + 资源地址（IMAGE_RESOURCE_DIRECTORY地址） == 下一层目录节点的起始位置，指向IMAGE_RESOURCE_DIR_STRING_U
最高位如果为0：指向 IMAGE_RESOURCE_DATA_ENTRY
*/															
typedef struct _IMAGE_RESOURCE_DIRECTORY_ENTRY {								
    union {						//目录项的名称、或者ID		
        struct {								
            DWORD NameOffset:31; 				//资源名偏移				
            DWORD NameIsString:1;				//最高位，1：NameOffset起作用，NameOffset+资源地址（IMAGE_RESOURCE_DIRECTORY地址） == 下一层目录节点的起始位置， 0：表示ID				
        };								
        DWORD   Name;				//资源/语言类型				
        WORD    Id;					//资源数字ID			
    };								
    union {								
        DWORD   OffsetToData;						//目录项指针		
        struct {								
            DWORD   OffsetToDirectory:31;								
            DWORD   DataIsDirectory:1;								
        };								
    };								
} IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;												

/*
8.3 资源ID
从NameString开始读取Length个Unicode字符
*/
typedef struct _IMAGE_RESOURCE_DIR_STRING_U {						
    WORD    Length;				//长度				
    WCHAR   NameString[ 1 ];	//第一个字符			
} IMAGE_RESOURCE_DIR_STRING_U, *PIMAGE_RESOURCE_DIR_STRING_U;	

/*
8.4 资源数据信息
*/
typedef struct _IMAGE_RESOURCE_DATA_ENTRY {
    DWORD   OffsetToData;//资源数据的RVA
    DWORD   Size;//资源数据的长度
    DWORD   CodePage;//代码页
    DWORD   Reserved;//保留字段
} IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;					

