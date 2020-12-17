### 可执行文件解析
支持Windows PE，Linux ELF等格式的可执行文件解析。

### Windows PE文件格式
1.DOS头
struct _IMAGE_DOS_HEADER {
    WORD e_magic;// 5a 4d * #MZ，dos头的魔数
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

2.NT头
struct _IMAGE_NT_HEADERS {
    DWORD Signature;//00 00 45 50
    _IMAGE_FILE_HEADER FileHeader;
    _IMAGE_OPTIONAL_HEADER OptionalHeader;
};
2.1标准PE头
struct _IMAGE_FILE_HEADER {
    WORD Machine;//01 4c * #程序运行的CPU型号：0x0 任何处理器/0x14C 386及后续处理器
    WORD NumberOfSections;//00 06 * #节（Section）数，PE文件时候分节的，即：PE文件中存在的节的总数,如果要新增节或者合并节 就要修改这个值.
    DWORD TimeDateStamp;//5f d2 c6 a7 * #时间戳：文件的创建时间(和操作系统的创建时间无关)，编译器填写的.
    DWORD PointerToSymbolTable;//00 00 00 00 #
    DWORD NumberOfSymbols;//00 00 00 00 #
    WORD SizeOfOptionalHeader;//00 e0 * #可选PE头的大小，32位PE文件默认E0h 64位PE文件默认为F0h  大小可以自定义.
    WORD Characteristics;//01 02 * #每个位有不同的含义，可执行文件值为10F 即0 1 2 3 8位置1
};

2.2可选PE头（大小不确定）
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
