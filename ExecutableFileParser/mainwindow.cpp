#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QMessageBox>
#include <QFileDialog>

void Char2Wchar(const char *chr, wchar_t *wchar, int size)
{
    MultiByteToWideChar( CP_ACP, 0, chr, strlen(chr)+1, wchar, size/sizeof(wchar[0]) );
}

void Wchar2Char(const wchar_t *wchar, char *chr, int length)
{
    WideCharToMultiByte( CP_ACP, 0, wchar, -1, chr, length, NULL, NULL );
}

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    setWindowTitle(APP_NAME);
    setWindowFlags(Qt::WindowCloseButtonHint);//只显示关闭按钮
    setFixedSize(1200, 800);
    ui->textEdit->setReadOnly(true);
    ui->labelStatus->setText("加载文件：");
    ui->statusBar->addWidget(ui->labelStatus);

    showDetail = false;
    pOutputResult = new QString[512];
    curLine = 0;
    fileBuffer.pBuffer = NULL;
    fileBuffer.size = 0;

    pDosHeader = NULL;
    pNTHeader = NULL;
    pPEHeader = NULL;
    pOptionHeader = NULL;
    pSectionHeader = NULL;

    pElf32_Ehdr = NULL;
    pElf64_Ehdr = NULL;
    pElf32_Shdr = NULL;
    pElf64_Shdr = NULL;

    connect(ui->actionAbout, &QAction::triggered, this, on_actionAbout_clicked);
    connect(ui->actionOpen, &QAction::triggered, this, on_actionOpen_clicked);
}

MainWindow::~MainWindow()
{
    cleanFileBuffer();
    if(pOutputResult != NULL) delete pOutputResult;
    delete ui;
}

void MainWindow::appendTextEdit(QString data)
{
    ui->textEdit->append(data);
    curLine++;
}

void MainWindow::cleanFileBuffer()
{
    if(fileBuffer.pBuffer != NULL){
        free(fileBuffer.pBuffer);
        fileBuffer.pBuffer = NULL;
        fileBuffer.size = 0;
        pDosHeader = NULL;
        pNTHeader = NULL;
        pPEHeader = NULL;
        pOptionHeader = NULL;
        pSectionHeader = NULL;

        pElf32_Ehdr = NULL;
        pElf64_Ehdr = NULL;
        pElf32_Shdr = NULL;
        pElf64_Shdr = NULL;

        ui->textEdit->setText("");
    }
}

//RVA = 运行时内存中真实地址 - ImageBase
int MainWindow::RVA2FOA(PVOID FileAddress, DWORD RVA, PDWORD pFOA)
{
    PIMAGE_DOS_HEADER pDosHeader				= (PIMAGE_DOS_HEADER)(FileAddress);
    PIMAGE_FILE_HEADER pFileHeader				= (PIMAGE_FILE_HEADER)((DWORD)pDosHeader + pDosHeader->e_lfanew + 4);
    PIMAGE_OPTIONAL_HEADER32 pOptionalHeader	= (PIMAGE_OPTIONAL_HEADER32)((DWORD)pFileHeader + sizeof(IMAGE_FILE_HEADER));
    PIMAGE_SECTION_HEADER pSectionGroup			= (PIMAGE_SECTION_HEADER)((DWORD)pOptionalHeader + pFileHeader->SizeOfOptionalHeader);

    //如果RVA在文件头中 或者 SectionAlignment等于FileAlignment 那么RVA等于FOA
    if (RVA < pOptionalHeader->SizeOfHeaders || pOptionalHeader->SectionAlignment == pOptionalHeader->FileAlignment)
    {
        *pFOA = RVA;
        return 0;
    }

    //循环判断RVA在节区中的位置，并确定FOA
    for (int i = 0; i < pFileHeader->NumberOfSections; i++)
    {
        if (RVA >= pSectionGroup[i].VirtualAddress && RVA < pSectionGroup[i].VirtualAddress + pSectionGroup[i].Misc.VirtualSize)
        {
            *pFOA = pSectionGroup[i].PointerToRawData + RVA - pSectionGroup[i].VirtualAddress;
            return 0;
        }
    }

    //没有找到地址
    LOG_DEBUG("地址转换失败!");
    return -1;
}

void MainWindow::on_actionOpen_clicked()
{
    fileName = QFileDialog::getOpenFileName(this, tr("文件对话框！"), "", tr("PE/ELF(*exe *dll *sys *so *o *);;""所有文件(*)"));
    if(fileName.size() < 1){
        return;
    }

    LOG_DEBUG("Select File Name=%s",fileName.toStdString().c_str());
    if(fileBuffer.pBuffer != NULL){
        cleanFileBuffer();
    }
    LoadFile(fileName.toStdString().c_str(), &fileBuffer.pBuffer, &fileBuffer.size);
    LOG_DEBUG("Load File Size=%d",fileBuffer.size);
    ui->labelStatus->setText("加载文件："+fileName);

    pDosHeader = (PIMAGE_DOS_HEADER)fileBuffer.pBuffer;
    if(CheckDosHeaderMagic(pDosHeader->e_magic) < 0){
        LOG_DEBUG("DOS头解析错误，这不是PE格式文件！");
        goto check_ELF;
    }

    pNTHeader = (PIMAGE_NT_HEADERS)((unsigned char *)fileBuffer.pBuffer+pDosHeader->e_lfanew);
    if(CheckPeHeaderMagic(pNTHeader->Signature) < 0){
        LOG_DEBUG("NT头解析错误，这不是PE格式文件！");
        goto check_ELF;
    }
    pPEHeader = (PIMAGE_FILE_HEADER)(((unsigned char *)pNTHeader) + 4);
    pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((unsigned char *)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
    pSectionHeader = (PIMAGE_SECTION_HEADER)((unsigned char *)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
    fileType = FILE_TYPE_PE;
    return ;

check_ELF:
    pElf32_Ehdr = (Elf32_Ehdr *)fileBuffer.pBuffer;
    //LOG_DEBUG("pElf32_Ehdr->e_ident=%x", *((DWORD *)pElf32_Ehdr->e_ident));
    if(CheckElfHeaderMagic(*((DWORD *)pElf32_Ehdr->e_ident)) < 0){
        QMessageBox::information(this, APP_NAME, "解析错误，这不是PE/ELF格式文件！");
        cleanFileBuffer();
    }

    fileType = FILE_TYPE_ELF;

    pElf32_Shdr = (Elf32_Shdr *)((unsigned char *)pElf32_Ehdr + pElf32_Ehdr->e_shoff);

    ELF_BIT_SIZE elfSize = CheckElfBitSize(pElf32_Ehdr->e_ident);
    if(elfSize == ELF_BIT_SIZE_32){
        return;
    }else if (elfSize == ELF_BIT_SIZE_64){
        pElf64_Ehdr = (Elf64_Ehdr *)fileBuffer.pBuffer;
        pElf64_Shdr = (Elf64_Shdr *)((unsigned char *)pElf64_Ehdr + pElf64_Ehdr->e_shoff);
        return;
    }else{
        QMessageBox::information(this, APP_NAME, "解析错误，非法的ELF文件！");
        cleanFileBuffer();
    }
}

void MainWindow::on_actionAbout_clicked()
{
    QMessageBox::information(this, APP_NAME, "可执行文件解析器（支持PE/ELF格式）\n版本：V1.0");
}


///////////////////////////////////////////////// PE File Parser ///////////////////////////////////////////
void MainWindow::on_actionParseDosHeader_triggered()
{
    if(fileBuffer.pBuffer == NULL || fileBuffer.size == 0){
        QMessageBox::information(this, APP_NAME, "还没有打开任何PE文件！");
        return;
    }

    if(fileType != FILE_TYPE_PE){
        QMessageBox::information(this, APP_NAME, "非法的PE文件！");
        return;
    }

    appendTextEdit("---------------------------------------DOS头[带[*]的是重点]---------------------------------------");
    char buf[1024] = {0};
    sprintf(buf, "                        e_magic:%04x                //[*]MZ，DOS头的幻数", pDosHeader->e_magic);
    appendTextEdit(QString(buf));
    memset(buf, 0, 1024);
    sprintf(buf, "                         e_cblp:%04x                //[Bytes on last page of file", pDosHeader->e_cblp);
    appendTextEdit(QString(buf));
    memset(buf, 0, 1024);
    sprintf(buf, "                           e_cp:%04x                //Pages in file", pDosHeader->e_cp);
    appendTextEdit(QString(buf));
    memset(buf, 0, 1024);
    sprintf(buf, "                         e_crlc:%04x                //Relocations", pDosHeader->e_crlc);
    appendTextEdit(QString(buf));
    memset(buf, 0, 1024);
    sprintf(buf, "                      e_cparhdr:%04x                //Size of header in paragraphs", pDosHeader->e_cparhdr);
    appendTextEdit(QString(buf));
    memset(buf, 0, 1024);
    sprintf(buf, "                     e_minalloc:%04x                //Minimum extra paragraphs needed", pDosHeader->e_minalloc);
    appendTextEdit(QString(buf));
    memset(buf, 0, 1024);
    sprintf(buf, "                     e_maxalloc:%04x                //Maximum extra paragraphs needed", pDosHeader->e_maxalloc);
    appendTextEdit(QString(buf));
    memset(buf, 0, 1024);
    sprintf(buf, "                           e_ss:%04x                //DOS代码的初始化堆栈SS值", pDosHeader->e_ss);
    appendTextEdit(QString(buf));
    memset(buf, 0, 1024);
    sprintf(buf, "                           e_sp:%04x                //DOS代码的初始化堆栈指针SP值", pDosHeader->e_sp);
    appendTextEdit(QString(buf));
    memset(buf, 0, 1024);
    sprintf(buf, "                         e_csum:%04x                //Checksum", pDosHeader->e_csum);
    appendTextEdit(QString(buf));
    memset(buf, 0, 1024);
    sprintf(buf, "                           e_ip:%04x                //DOS代码入口IP", pDosHeader->e_ip);
    appendTextEdit(QString(buf));
    memset(buf, 0, 1024);
    sprintf(buf, "                           e_cs:%04x                //DOS代码的入口CS", pDosHeader->e_cs);
    appendTextEdit(QString(buf));
    memset(buf, 0, 1024);
    sprintf(buf, "                       e_lfarlc:%04x                //File address of relocation table", pDosHeader->e_lfarlc);
    appendTextEdit(QString(buf));
    memset(buf, 0, 1024);
    sprintf(buf, "                         e_ovno:%04x                //Overlay number", pDosHeader->e_ovno);
    appendTextEdit(QString(buf));
    memset(buf, 0, 1024);
    sprintf(buf, "                          e_res:%04x %04x %04x %04x //Reserved words", pDosHeader->e_res[0],pDosHeader->e_res[1],pDosHeader->e_res[2],pDosHeader->e_res[3]);
    appendTextEdit(QString(buf));
    memset(buf, 0, 1024);
    sprintf(buf, "                        e_oemid:%04x                //OEM identifier (for e_oeminfo)", pDosHeader->e_oemid);
    appendTextEdit(QString(buf));
    memset(buf, 0, 1024);
    sprintf(buf, "                      e_oeminfo:%04x                //OEM information; e_oemid specific", pDosHeader->e_oeminfo);
    appendTextEdit(QString(buf));
    memset(buf, 0, 1024);
    sprintf(buf, "                         e_res2:%04x %04x %04x %04x %04x %04x %04x %04x %04x %04x //Reserved words.", pDosHeader->e_res2[0],
            pDosHeader->e_res2[1],pDosHeader->e_res2[2],pDosHeader->e_res2[3],pDosHeader->e_res2[4],pDosHeader->e_res2[5],
            pDosHeader->e_res2[6],pDosHeader->e_res2[7],pDosHeader->e_res2[8],pDosHeader->e_res2[9]);
    appendTextEdit(QString(buf));
    memset(buf, 0, 1024);
    sprintf(buf, "                       e_lfanew:%08x            //[*]PE头相对于文件的偏移，用于定位PE文件（具体值会由于编译器不同，具体值不一定）", pDosHeader->e_lfanew);
    appendTextEdit(QString(buf));

}

void MainWindow::on_actionParsePeHeader_triggered()
{
    if(fileBuffer.pBuffer == NULL || fileBuffer.size == 0){
        QMessageBox::information(this, APP_NAME, "还没有打开任何PE文件！");
        return;
    }

    if(fileType != FILE_TYPE_PE){
        QMessageBox::information(this, APP_NAME, "非法的PE文件！");
        return;
    }

    appendTextEdit("---------------------------------------NT头[带[*]的是重点]---------------------------------------");
    char buf[1024] = {0};
    sprintf(buf, "                      Signature:%08x            //[*]NT头标识", pNTHeader->Signature);
    appendTextEdit(QString(buf));

    pPEHeader = (PIMAGE_FILE_HEADER)(((unsigned char *)pNTHeader) + 4);
    appendTextEdit("---------------------------------------PE头[带[*]的是重点]---------------------------------------");
    memset(buf, 0, 1024);
    sprintf(buf, "                        Machine:%04x                //[*]程序运行的CPU型号：0x0 任何处理器/0x14C 386及后续处理器", pPEHeader->Machine);
    appendTextEdit(QString(buf));
    memset(buf, 0, 1024);
    sprintf(buf, "               NumberOfSections:%04x                //[*]节（Section）数，PE文件是分节的，即：PE文件中存在的节的总数,如果要新增节或者合并节，就要修改这个值", pPEHeader->NumberOfSections);
    appendTextEdit(QString(buf));
    memset(buf, 0, 1024);
    sprintf(buf, "                  TimeDateStamp:%08x            //[*]时间戳：文件的创建时间(和操作系统的创建时间无关)，编译器填写的.", pPEHeader->TimeDateStamp);
    appendTextEdit(QString(buf));
    memset(buf, 0, 1024);
    sprintf(buf, "           PointerToSymbolTable:%08x            //指向符号表(主要用于调试)", pPEHeader->PointerToSymbolTable);
    appendTextEdit(QString(buf));
    memset(buf, 0, 1024);
    sprintf(buf, "                NumberOfSymbols:%08x            //符号表中符号个数(同上)", pPEHeader->NumberOfSymbols);
    appendTextEdit(QString(buf));
    memset(buf, 0, 1024);
    sprintf(buf, "           SizeOfOptionalHeader:%04x                //[*]可选PE头的大小，32位PE文件默认E0h 64位PE文件默认为F0h  大小可以自定义.", pPEHeader->SizeOfOptionalHeader);
    appendTextEdit(QString(buf));
    memset(buf, 0, 1024);
    sprintf(buf, "                Characteristics:%04x                //[*]每个位有不同的含义，可执行文件值为10F 即0 1 2 3 8位置1 ", pPEHeader->Characteristics);
    appendTextEdit(QString(buf));
    if(showDetail){
        appendTextEdit(QString(""));
        appendTextEdit(QString("Characteristics（文件属性） 特征值对照表："));
        appendTextEdit(QString("[值:0001h]     [IMAGE_FILE_RELOCS_STRIPPED          // Relocation info stripped from file.(重定位信息被移去)]"));
        appendTextEdit(QString("[值:0002h]     [IMAGE_FILE_EXECUTABLE_IMAGE         // File is executable (i.e. no unresolved externel references).(文件可执行)]"));
        appendTextEdit(QString("[值:0004h]     [IMAGE_FILE_LINE_NUMS_STRIPPED       // Line nunbers stripped from file.(行号被移去)]"));
        appendTextEdit(QString("[值:0008h]     [IMAGE_FILE_LOCAL_SYMS_STRIPPED      // Local symbols stripped from file.(符号被移去)]"));
        appendTextEdit(QString("[值:0010h]     [IMAGE_FILE_AGGRESIVE_WS_TRIM        // Agressively trim working set.(主动调整工作区)]"));
        appendTextEdit(QString("[值:0020h]     [IMAGE_FILE_LARGE_ADDRESS_AWARE      // App can handle >2gb addresses.(高地址警告)]"));
        appendTextEdit(QString("[值:0080h]     [IMAGE_FILE_BYTES_REVERSED_LO        // Bytes of machine word are reversed.(处理机的低位字节是相反的)]"));
        appendTextEdit(QString("[值:0100h]     [IMAGE_FILE_32BIT_MACHINE            // 32 bit word machine. (32位机器)]"));
        appendTextEdit(QString("[值:0200h]     [IMAGE_FILE_DEBUG_STRIPPED           // Debugging info stripped from file in .DBG file.(.DBG文件的调试信息被移去)]"));
        appendTextEdit(QString("[值:0400h]     [IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP  // If Image is on removable media, copy and run from the swap file.(如果映象文件是在可移动媒体中,则先复制到交换文件后再运行)]"));
        appendTextEdit(QString("[值:0800h]     [IMAGE_FILE_NET_RUN_FROM_SWAP        // If Image is on Net, copy and run from the swap file.(如果映象文件是在网络中,则复制到交换文件后才运行)]"));
        appendTextEdit(QString("[值:1000h]     [IMAGE_FILE_SYSTEM                   // System File.(系统文件)]"));
        appendTextEdit(QString("[值:2000h]     [IMAGE_FILE_DLL                      // File is a DLL.(文件是DLL文件)]"));
        appendTextEdit(QString("[值:4000h]     [IMAGE_FILE_UP_SYSTEM_ONLY           // File should only be run on a UP machine.(文件只能运行在单处理器上)]"));
        appendTextEdit(QString("[值:8000h]     [IMAGE_FILE_BYTES_REVERSED_HI        // Bytes of machine word are reversed.(处理机的高位字节是相反的)]"));
    }
}

void MainWindow::on_actionParseOptionalHeader_triggered()
{
    if(fileBuffer.pBuffer == NULL || fileBuffer.size == 0){
        QMessageBox::information(this, APP_NAME, "还没有打开任何PE文件！");
        return;
    }

    if(fileType != FILE_TYPE_PE){
        QMessageBox::information(this, APP_NAME, "非法的PE文件！");
        return;
    }

    appendTextEdit("---------------------------------------可选PE头[带[*]的是重点]---------------------------------------");
    char buf[1024] = {0};
    sprintf(buf, "                          Magic:%04x                //[*]标志字(幻数),说明文件类型：10B 32位下的PE文件，20B 64位下的PE文件", pOptionHeader->Magic);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, "             MajorLinkerVersion:%02x                  //链接器主版本号", pOptionHeader->MajorLinkerVersion);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, "             MinorLinkerVersion:%02x                  //链接器次版本号", pOptionHeader->MinorLinkerVersion);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, "                     SizeOfCode:%08x            //[*]代码段(块)大小,所有Code Section总共的大小，必须是FileAlignment的整数倍 编译器填的", pOptionHeader->SizeOfCode);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, "          SizeOfInitializedData:%08x            //[*]已初始化数据块大小.即在编译时所构成的块的大小(不包括代码段),但这个数据并不太准确，必须是FileAlignment的整数倍 编译器填的", pOptionHeader->SizeOfInitializedData);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, "        SizeOfUninitializedData:%08x            //[*]未初始化数据块大小.装载程序要在虚拟地址空间中为这些数据约定空间.未初始化数据通常在.bbs块中，必须是FileAlignment的整数倍 编译器填的", pOptionHeader->SizeOfUninitializedData);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, "            AddressOfEntryPoint:%08x            //[*]程序开始执行的入口地址/入口点EP(RVA).这是一个相对虚拟地址，ImageBase+AddressOfEntryPoint才是真正的程序入口", pOptionHeader->AddressOfEntryPoint);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, "                     BaseOfCode:%08x            //[*]代码段(块)起始地址，编译器填的", pOptionHeader->BaseOfCode);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, "                     BaseOfData:%08x            //[*]数据段(块)起始地址，编译器填的", pOptionHeader->BaseOfData);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, "                      ImageBase:%08x            //[*]基址,程序默认装入的基地址，内存镜像基址，ImageBase+AddressOfEntryPoint才是真正的程序入口", pOptionHeader->ImageBase);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, "               SectionAlignment:%08x            //[*]内存中的节(块Section)的对齐值,常为:0x1000或0x04", pOptionHeader->SectionAlignment);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, "                  FileAlignment:%08x            //[*]文件中的节(块Section)的对齐值,常为:0x1000或0x200或0x04", pOptionHeader->FileAlignment);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, "     MaorOperatingSystemVersion:%04x                //操作系统主版本号", pOptionHeader->MajorOperatingSystemVersion);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, "    MinorOperatingSystemVersion:%04x                //操作系统次版本号", pOptionHeader->MinorOperatingSystemVersion);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, "              MajorImageVersion:%04x                //该可执行文件的主版本号,由程序员自定义", pOptionHeader->MajorImageVersion);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, "              MinorImageVersion:%04x                //该可执行文件的次版本号,由程序员自定义", pOptionHeader->MinorImageVersion);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, "          MajorSubsystemVersion:%04x                //所需子系统主版本号", pOptionHeader->MajorSubsystemVersion);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, "          MinorSubsystemVersion:%04x                //所需子系统次版本号", pOptionHeader->MinorSubsystemVersion);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, "              Win32VersionValue:%08x            //保留,总是0", pOptionHeader->Win32VersionValue);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, "                    SizeOfImage:%08x            //[*]映像大小(映像装入内存后的总尺寸/内存中整个PE映像的尺寸),即：内存中整个PE文件的映射的尺寸（已经按内存对齐后的大小），可以比实际的值大，但必须是SectionAlignment的整数倍", pOptionHeader->SizeOfImage);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, "                  SizeOfHeaders:%08x            //[*]首部及块表(首部+块表)的大小],所有头+节表按照文件对齐后的大小，否则加载会出错", pOptionHeader->SizeOfHeaders);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, "                       CheckSum:%04x                //[*]校验和，一些系统文件有要求.用来判断文件是否被修改.", pOptionHeader->CheckSum);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, "                      Subsystem:%04x                //子系统:Windows 控制台/字符子系统(Image runs in the Windows character subsystem.)", pOptionHeader->Subsystem);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, "             DllCharacteristics:%04x                //DLLMain()函数何时被调用.当文件为DLL程序时使用,默认值为0", pOptionHeader->DllCharacteristics);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, "             SizeOfStackReserve:%08x            //[*]初始化时为线程保留的栈大小", pOptionHeader->SizeOfStackReserve);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, "              SizeOfStackCommit:%08x            //[*]初始化时线程实际使用的栈大小 ", pOptionHeader->SizeOfStackCommit);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, "              SizeOfHeapReserve:%08x            //[*]初始化时为进程保留的堆大小", pOptionHeader->SizeOfHeapReserve);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, "               SizeOfHeapCommit:%08x            //[*]初始化时进程实际使用的堆大小", pOptionHeader->SizeOfHeapCommit);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, "                    LoaderFlags:%08x            //设置自动调用断点或调试器.与调试有关,默认值为0", pOptionHeader->LoaderFlags);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, "            NumberOfRvaAndSizes:%08x            //数据目录结构的数量(项数)", pOptionHeader->NumberOfRvaAndSizes);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, "_IMAGE_DATA_DIRECTORY DataDirectory[16];            //数据目录表,如下:(16项,每个成员占8字节)", pOptionHeader->DataDirectory);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, "_IMAGE_DATA_DIRECTORY DataDirectory[16](数据目录表，带[*]的重点掌握)结构如下：", pOptionHeader->DataDirectory);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, "索引   数据(RVA)     大小    ", pOptionHeader->DataDirectory);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, " 00    %08x      %08x        //[*]导出表", pOptionHeader->DataDirectory[0].VirtualAddress, pOptionHeader->DataDirectory[0].Size);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, " 01    %08x      %08x        //[*]导入表", pOptionHeader->DataDirectory[1].VirtualAddress, pOptionHeader->DataDirectory[1].Size);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, " 02    %08x      %08x        //资源", pOptionHeader->DataDirectory[2].VirtualAddress, pOptionHeader->DataDirectory[2].Size);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, " 03    %08x      %08x        //异常", pOptionHeader->DataDirectory[3].VirtualAddress, pOptionHeader->DataDirectory[3].Size);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, " 04    %08x      %08x        //安全证书", pOptionHeader->DataDirectory[4].VirtualAddress, pOptionHeader->DataDirectory[4].Size);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, " 05    %08x      %08x        //[*]重定位表", pOptionHeader->DataDirectory[5].VirtualAddress, pOptionHeader->DataDirectory[5].Size);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, " 06    %08x      %08x        //调试信息", pOptionHeader->DataDirectory[6].VirtualAddress, pOptionHeader->DataDirectory[6].Size);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, " 07    %08x      %08x        //版权所有", pOptionHeader->DataDirectory[7].VirtualAddress, pOptionHeader->DataDirectory[7].Size);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, " 08    %08x      %08x        //全局指针", pOptionHeader->DataDirectory[8].VirtualAddress, pOptionHeader->DataDirectory[8].Size);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, " 09    %08x      %08x        //TLS（Tread local storage）表", pOptionHeader->DataDirectory[9].VirtualAddress, pOptionHeader->DataDirectory[9].Size);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, " 10    %08x      %08x        //加载配置", pOptionHeader->DataDirectory[10].VirtualAddress, pOptionHeader->DataDirectory[10].Size);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, " 11    %08x      %08x        //[*]绑定导入", pOptionHeader->DataDirectory[11].VirtualAddress, pOptionHeader->DataDirectory[11].Size);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, " 12    %08x      %08x        //[*]IAT（Import Address Table）表", pOptionHeader->DataDirectory[12].VirtualAddress, pOptionHeader->DataDirectory[12].Size);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, " 13    %08x      %08x        //延迟导", pOptionHeader->DataDirectory[13].VirtualAddress, pOptionHeader->DataDirectory[13].Size);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, " 14    %08x      %08x        //COM", pOptionHeader->DataDirectory[14].VirtualAddress, pOptionHeader->DataDirectory[14].Size);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, " 15    %08x      %08x        //保留", pOptionHeader->DataDirectory[15].VirtualAddress, pOptionHeader->DataDirectory[15].Size);
    appendTextEdit(QString(buf));

}

void MainWindow::on_actionClearScreen_triggered()
{
    ui->textEdit->setText("");
}

void MainWindow::on_actionParseSection_triggered()
{
    if(fileBuffer.pBuffer == NULL || fileBuffer.size == 0){
        QMessageBox::information(this, APP_NAME, "还没有打开任何PE文件！");
        return;
    }

    if(fileType != FILE_TYPE_PE){
        QMessageBox::information(this, APP_NAME, "非法的PE文件！");
        return;
    }

    int indexSection = 0;
    unsigned char *VA,*RVA,*FOA;;
    QString sectionInfo;
    int sectionNumber = pPEHeader->NumberOfSections;
    PIMAGE_SECTION_HEADER pCurrentSectionHeader = pSectionHeader;;
    appendTextEdit("---------------------------------------块表|区段|节表[带[*]的是重点]---------------------------------------");
    char buf[1024] = {0};
    sprintf(buf, "                      section数:%04x                //IMAGE_FILE_HEADER(PE Header结构体)的NumberOfSections字段", sectionNumber);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, "区段名称      内存中偏移地址    内存中大小    文件中偏移    文件中大小\n");
    sectionInfo += buf;

    if(showDetail){
        memset(buf, 0, 1024);
        sprintf(buf, "块表|区段|节表 相关概念：", pCurrentSectionHeader->Name);
        appendTextEdit(QString(buf));

        memset(buf, 0, 1024);
        sprintf(buf, " VA: 全名virtualAddress 虚拟地址. 就是内存中虚拟地址. 例如 0x00401000", pCurrentSectionHeader->Name);
        appendTextEdit(QString(buf));

        memset(buf, 0, 1024);
        sprintf(buf, "RVA: RVA就是相对虚拟偏移. 就是偏移地址. 可以理解为文件被装载到虚拟内存(拉伸)后相对于基址的偏移地址。例如 0x1000. 虚拟地址0x00401000的RVA就是 0x1000. RVA = 虚拟地址-ImageBase", pCurrentSectionHeader->Name);
        appendTextEdit(QString(buf));

        memset(buf, 0, 1024);
        sprintf(buf, "FOA: 文件偏移. 就是文件中所在的地址.可以理解为文件在磁盘上存放时相对于文件开头的偏移地址。", pCurrentSectionHeader->Name);
        appendTextEdit(QString(buf));
    }

    appendTextEdit("--------------------------------------------------------------------------------------------------------");

    for(indexSection=0; indexSection<sectionNumber; indexSection++){
        memset(buf, 0, 1024);
        sprintf(buf, "                           Name:%s               //[*]名称,长度:8位(16字节)的ASCII码，如：.text .bss .data", pCurrentSectionHeader->Name);
        appendTextEdit(QString(buf));

        memset(buf, 0, 1024);
        sprintf(buf, "              (Msic)VirtualSize:%08x            //[*]内存中大小(对齐前的长度)，该节在没有对齐之前的真实长度（对齐解释：如以0x200大小对齐，0x192就会通过补0变成0x200），这个值可能不准确（可能被别人修改）", pCurrentSectionHeader->Misc);
        appendTextEdit(QString(buf));

        memset(buf, 0, 1024);
        sprintf(buf, "                 VirtualAddress:%08x            //[*]内存中偏移(该块的RVA)，VirtualAddress在内存中的偏移，相对于ImageBase偏移(简单理解：离ImageBase多远），在内存中有意义", pCurrentSectionHeader->VirtualAddress);
        appendTextEdit(QString(buf));

        memset(buf, 0, 1024);
        sprintf(buf, "                  SizeOfRawData:%08x            //[*]文件中大小(对齐后的长度)，节在文件中对齐后的大小", pCurrentSectionHeader->SizeOfRawData);
        appendTextEdit(QString(buf));

        memset(buf, 0, 1024);
        sprintf(buf, "               PointerToRawData:%08x            //[*]文件中偏移.节区在文件中的偏移（对齐后），在文件中", pCurrentSectionHeader->PointerToRawData);
        appendTextEdit(QString(buf));

        memset(buf, 0, 1024);
        sprintf(buf, "           PointerToRelocations:%08x            //[*]在OBJ文件中使用,重定位的偏移.在obj文件中使用，对exe无意义", pCurrentSectionHeader->PointerToRelocations);
        appendTextEdit(QString(buf));

        memset(buf, 0, 1024);
        sprintf(buf, "           PointerToLinenumbers:%08x            //[*]行号表的偏移,提供调试.", pCurrentSectionHeader->PointerToLinenumbers);
        appendTextEdit(QString(buf));

        memset(buf, 0, 1024);
        sprintf(buf, "            NumberOfRelocations:%04x                //[*]在obj文件中使用，重定位项数目，对exe无意义", pCurrentSectionHeader->NumberOfRelocations);
        appendTextEdit(QString(buf));

        memset(buf, 0, 1024);
        sprintf(buf, "            NumberOfLinenumbers:%04x                //[*]行号表中行号的数量，调试的时候使用", pCurrentSectionHeader->NumberOfLinenumbers);
        appendTextEdit(QString(buf));

        memset(buf, 0, 1024);
        sprintf(buf, "                Characteristics:%08x            //[*]节的属性", pCurrentSectionHeader->Characteristics);
        appendTextEdit(QString(buf));

        memset(buf, 0, 1024);
        sprintf(buf, " ");
        appendTextEdit(QString(buf));

        memset(buf, 0, 1024);
        sprintf(buf, "%8s      0x%08x      0x%08x    0x%08x    0x%08x\n", pCurrentSectionHeader->Name, pCurrentSectionHeader->VirtualAddress, pCurrentSectionHeader->Misc.VirtualSize, pCurrentSectionHeader->PointerToRawData, pCurrentSectionHeader->SizeOfRawData);
        sectionInfo += buf;

        pCurrentSectionHeader = (PIMAGE_SECTION_HEADER)((unsigned char *)(&pCurrentSectionHeader->Characteristics) + sizeof(DWORD));
    }
    appendTextEdit(" ");
    appendTextEdit(sectionInfo);


    if(showDetail){
        appendTextEdit(QString(""));
        appendTextEdit(QString("Characteristics（属性块|区|节） 特征值对照表："));
        appendTextEdit(QString("[值:00000020h]   [IMAGE_SCN_CNT_CODE                // Section contains code.(包含可执行代码)]"));
        appendTextEdit(QString("[值:00000040h]   [IMAGE_SCN_CNT_INITIALIZED_DATA    // Section contains initialized data.(该块包含已初始化的数据)]"));
        appendTextEdit(QString("[值:00000080h]   [IMAGE_SCN_CNT_UNINITIALIZED_DATA  // Section contains uninitialized data.(该块包含未初始化的数据)]"));
        appendTextEdit(QString("[值:00000200h]   [IMAGE_SCN_LNK_INFO                // Section contains comments or some other type of information.]"));
        appendTextEdit(QString("[值:00000800h]   [IMAGE_SCN_LNK_REMOVE              // Section contents will not become part of image.]"));
        appendTextEdit(QString("[值:00001000h]   [IMAGE_SCN_LNK_COMDAT              // Section contents comdat.]"));
        appendTextEdit(QString("[值:00004000h]   [IMAGE_SCN_NO_DEFER_SPEC_EXC       // Reset speculative exceptions handling bits in the TLB entries for this section.]"));
        appendTextEdit(QString("[值:00008000h]   [IMAGE_SCN_GPREL                   // Section content can be accessed relative to GP.]"));
        appendTextEdit(QString("[值:00500000h]   [IMAGE_SCN_ALIGN_16BYTES           // Default alignment if no others are specified.]"));
        appendTextEdit(QString("[值:01000000h]   [IMAGE_SCN_LNK_NRELOC_OVFL         // Section contains extended relocations.]"));
        appendTextEdit(QString("[值:02000000h]   [IMAGE_SCN_MEM_DISCARDABLE         // Section can be discarded.]"));
        appendTextEdit(QString("[值:04000000h]   [IMAGE_SCN_MEM_NOT_CACHED          // Section is not cachable.]"));
        appendTextEdit(QString("[值:08000000h]   [IMAGE_SCN_MEM_NOT_PAGED           // Section is not pageable.]"));
        appendTextEdit(QString("[值:10000000h]   [IMAGE_SCN_MEM_SHARED              // Section is shareable(该块为共享块).]"));
        appendTextEdit(QString("[值:20000000h]   [IMAGE_SCN_MEM_EXECUTE             // Section is executable.(该块可执行)]"));
        appendTextEdit(QString("[值:40000000h]   [IMAGE_SCN_MEM_READ                // Section is readable.(该块可读)]"));
        appendTextEdit(QString("[值:80000000h]   [IMAGE_SCN_MEM_WRITE               // Section is writeable.(该块可写)]"));
    }
}

void MainWindow::on_actionPeDetailParser_triggered()
{
    if(fileBuffer.pBuffer == NULL || fileBuffer.size == 0){
        QMessageBox::information(this, APP_NAME, "还没有打开任何PE文件！");
        return;
    }

    if(fileType != FILE_TYPE_PE){
        QMessageBox::information(this, APP_NAME, "非法的PE文件！");
        return;
    }

    showDetail = true;
    on_actionClearScreen_triggered();
    on_actionParseDosHeader_triggered();
    on_actionParsePeHeader_triggered();
    on_actionParseOptionalHeader_triggered();
    on_actionParseSection_triggered();
    on_actionExportTable_triggered();
    on_actionBaseRelocationTable_triggered();
    on_actionImportTable_triggered();
    on_actionBoundImportTable_triggered();
    on_actionResourceTable_triggered();
    showDetail = false;
}

void MainWindow::on_actionExportTable_triggered()
{
    if(fileBuffer.pBuffer == NULL || fileBuffer.size == 0){
        QMessageBox::information(this, APP_NAME, "还没有打开任何PE文件！");
        return;
    }

    if(fileType != FILE_TYPE_PE){
        QMessageBox::information(this, APP_NAME, "非法的PE文件！");
        return;
    }

    appendTextEdit("---------------------------------------导出表---------------------------------------");

    char buf[1024] = {0};
    sprintf(buf,"导出表在可选PE头数据目录的索引0项，pOptionHeader->DataDirectory[0].VirtualAddress=%08x",pOptionHeader->DataDirectory[0].VirtualAddress);
    appendTextEdit(QString(buf));

    if(pOptionHeader->DataDirectory[0].VirtualAddress == 0x0){
        appendTextEdit("ERROR:该PE文件无导出表");
        //QMessageBox::information(this, APP_NAME, "该PE文件无导出表！");
        return;
    }

    DWORD FOA;
    RVA2FOA(fileBuffer.pBuffer, pOptionHeader->DataDirectory[0].VirtualAddress, &FOA);
    LOG_DEBUG("FOA=%x", FOA);
    PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(fileBuffer.pBuffer + FOA);


    memset(buf, 0, 1024);
    sprintf(buf, "                Characteristics:%08x            //未使用", pExportDirectory->Characteristics);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, "                  TimeDateStamp:%08x            //时间戳", pExportDirectory->TimeDateStamp);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, "                   MajorVersion:%04x                //未使用", pExportDirectory->MajorVersion);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, "                   MinorVersion:%04x                //未使用", pExportDirectory->MinorVersion);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, "                           Name:%08x            //[*]指向该导出表文件名字符串", pExportDirectory->Name);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, "                           Base:%08x            //[*]导出函数起始序号", pExportDirectory->Base);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, "              NumberOfFunctions:%08x            //[*]有导出函数的个数", pExportDirectory->NumberOfFunctions);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, "                  NumberOfNames:%08x            //[*]以函数名字导出的函数个数", pExportDirectory->NumberOfNames);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, "             AddressOfFunctions:%08x            //[*]导出函数地址表RVA", pExportDirectory->AddressOfFunctions);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, "                 AddressOfNames:%08x            //[*]导出函数名称表RVA", pExportDirectory->AddressOfNames);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, "          AddressOfNameOrdinals:%08x            //[*]导出函数序号表RVA", pExportDirectory->AddressOfNameOrdinals);
    appendTextEdit(QString(buf));

    appendTextEdit("");

    memset(buf, 0, 1024);
    sprintf(buf, "索引   导出序号       函数地址（RVA）   函数名称");
    appendTextEdit(QString(buf));

    DWORD FOA_AddressOfFunctions = 0;
    DWORD FOA_AddressOfNames = 0;
    DWORD FOA_AddressOfNameOrdinals = 0;
    RVA2FOA(fileBuffer.pBuffer, pExportDirectory->AddressOfFunctions, &FOA_AddressOfFunctions);
    RVA2FOA(fileBuffer.pBuffer, pExportDirectory->AddressOfNames, &FOA_AddressOfNames);
    RVA2FOA(fileBuffer.pBuffer, pExportDirectory->AddressOfNameOrdinals, &FOA_AddressOfNameOrdinals);
    LOG_DEBUG("FOA_AddressOfFunctions=%x", FOA_AddressOfFunctions);
    LOG_DEBUG("FOA_AddressOfNames=%x", FOA_AddressOfNames);
    LOG_DEBUG("FOA_AddressOfNameOrdinals=%x", FOA_AddressOfNameOrdinals);
    DWORD *pAddressOfFunctions = (DWORD *)(fileBuffer.pBuffer + FOA_AddressOfFunctions);
    DWORD *pAddressOfNames = (DWORD *)(fileBuffer.pBuffer + FOA_AddressOfNames);
    WORD *pAddressOfNameOrdinals = (WORD *)(fileBuffer.pBuffer + FOA_AddressOfNameOrdinals);

    DWORD FOA_FunctionNames = 0;
    WORD index = 0;
    for(int i=0; i < pExportDirectory->NumberOfFunctions; i++)
    {
        index = pAddressOfNameOrdinals[i];
        memset(buf, 0, 1024);
        RVA2FOA(fileBuffer.pBuffer, pAddressOfNames[i], &FOA_FunctionNames);
        //LOG_DEBUG("index=%04x, pAddressOfFunctions[index]=%08x, %s", index, pAddressOfFunctions[index], fileBuffer.pBuffer + FOA_FunctionNames);
        sprintf(buf, " %02x    %04x          %08x          %s", i,index,pAddressOfFunctions[index],fileBuffer.pBuffer + FOA_FunctionNames);
        appendTextEdit(QString(buf));
    }
}

void MainWindow::on_actionBaseRelocationTable_triggered()
{
    if(fileBuffer.pBuffer == NULL || fileBuffer.size == 0){
        QMessageBox::information(this, APP_NAME, "还没有打开任何PE文件！");
        return;
    }

    if(fileType != FILE_TYPE_PE){
        QMessageBox::information(this, APP_NAME, "非法的PE文件！");
        return;
    }

    appendTextEdit("---------------------------------------重定位表---------------------------------------");

    char buf[1024] = {0};
    sprintf(buf,"重定位表在可选PE头数据目录的索引5项，pOptionHeader->DataDirectory[5].VirtualAddress=%08x",pOptionHeader->DataDirectory[5].VirtualAddress);
    appendTextEdit(QString(buf));

    if(pOptionHeader->DataDirectory[5].VirtualAddress == 0x0){
        appendTextEdit("ERROR:该PE文件无重定位表");
        return;
    }

    DWORD FOA;
    RVA2FOA(fileBuffer.pBuffer, pOptionHeader->DataDirectory[5].VirtualAddress, &FOA);
    LOG_DEBUG("FOA=%x", FOA);
    PIMAGE_BASE_RELOCATION pBaseRelocation = (PIMAGE_BASE_RELOCATION)(fileBuffer.pBuffer + FOA);
    PIMAGE_BASE_RELOCATION pSaveBaseRelocation = pBaseRelocation;

    memset(buf, 0, 1024);
    sprintf(buf, "地址（RVA）       大小（字节）");
    appendTextEdit(QString(buf));
    while(pBaseRelocation->VirtualAddress!=0x0 && pBaseRelocation->SizeOfBlock!=0x0)
    {
        memset(buf, 0, 1024);
        sprintf(buf, "%08x          %08x", pBaseRelocation->VirtualAddress,pBaseRelocation->SizeOfBlock);
        appendTextEdit(QString(buf));
        pBaseRelocation = (PIMAGE_BASE_RELOCATION)((unsigned char *)pBaseRelocation + pBaseRelocation->SizeOfBlock);
    }

    appendTextEdit("");
    memset(buf, 0, 1024);
    sprintf(buf, "详细解析：");
    appendTextEdit(QString(buf));

    DWORD RVA = 0;
    DWORD size = 0;
    WORD *pTypeOffset = NULL;
    WORD offset = 0;
    WORD magic = 0;
    pBaseRelocation = pSaveBaseRelocation;
    while(pBaseRelocation->VirtualAddress!=0x0 && pBaseRelocation->SizeOfBlock!=0x0)
    {
        memset(buf, 0, 1024);
        sprintf(buf, "RVA:%08x      大小:%08x", pBaseRelocation->VirtualAddress, pBaseRelocation->SizeOfBlock);
        appendTextEdit(QString(buf));
        memset(buf, 0, 1024);
        sprintf(buf, "真实RVA           属性");
        appendTextEdit(QString(buf));

        //详细解析
        size = (pBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION))/2;
        for(WORD i=0; i<size; i++)
        {
            pTypeOffset = (WORD *)((unsigned char *)pBaseRelocation + sizeof(IMAGE_BASE_RELOCATION) + sizeof(WORD)*i);
            magic = 0xF & ((*pTypeOffset) >> 12);
            offset = (*pTypeOffset) & 0xFFF;
            if(magic == IMAGE_REL_BASED_HIGHLOW){
                RVA2FOA(fileBuffer.pBuffer,  pBaseRelocation->VirtualAddress + offset, &FOA);
                memset(buf, 0, 1024);
                sprintf(buf, "%08x          %04x      IMAGE_REL_BASED_HIGHLOW    //需要修改", pBaseRelocation->VirtualAddress+offset, FOA);
                appendTextEdit(QString(buf));
            }
            if(magic == IMAGE_REL_BASED_ABSOLUTE){
                memset(buf, 0, 1024);
                sprintf(buf, "填充数据                                 //不需要修改", pBaseRelocation->VirtualAddress+offset);
                appendTextEdit(QString(buf));
            }

            /*
            //此段代码也正确
            RVA = *((WORD *)((unsigned char *)pBaseRelocation + sizeof(IMAGE_BASE_RELOCATION) + sizeof(WORD)*i));
            if(RVA / 0x3000){
                RVA2FOA(fileBuffer.pBuffer, RVA % 0x3000 + pBaseRelocation->VirtualAddress, &FOA);
                LOG_DEBUG("RVA=%x,FOA=%x",RVA % 0x3000, FOA % 0x3000);
                memset(buf, 0, 1024);
                sprintf(buf, "%08x          %04x      IMAGE_REL_BASED_HIGHLOW    //需要修改", pBaseRelocation->VirtualAddress+RVA % 0x3000, FOA % 0x3000);
                appendTextEdit(QString(buf));
            }
            else
            {
                memset(buf, 0, 1024);
                sprintf(buf, "填充数据                                 //不需要修改");
                appendTextEdit(QString(buf));
            }
            */
        }

        appendTextEdit("");
        pBaseRelocation = (PIMAGE_BASE_RELOCATION)((unsigned char *)pBaseRelocation + pBaseRelocation->SizeOfBlock);
    }
}

void MainWindow::on_actionImportTable_triggered()
{
    if(fileBuffer.pBuffer == NULL || fileBuffer.size == 0){
        QMessageBox::information(this, APP_NAME, "还没有打开任何PE文件！");
        return;
    }

    if(fileType != FILE_TYPE_PE){
        QMessageBox::information(this, APP_NAME, "非法的PE文件！");
        return;
    }

    appendTextEdit("---------------------------------------导入表---------------------------------------");

    char buf[1024] = {0};
    sprintf(buf,"导入表在可选PE头数据目录的索引1项，pOptionHeader->DataDirectory[1].VirtualAddress=%08x",pOptionHeader->DataDirectory[1].VirtualAddress);
    appendTextEdit(QString(buf));

    if(pOptionHeader->DataDirectory[1].VirtualAddress == 0x0){
        appendTextEdit("ERROR:该PE文件无导入表");
        return;
    }

    DWORD FOA;
    RVA2FOA(fileBuffer.pBuffer, pOptionHeader->DataDirectory[1].VirtualAddress, &FOA);
    LOG_DEBUG("FOA=%x", FOA);
    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(fileBuffer.pBuffer + FOA);

    WORD HIT = 0;
    PIMAGE_THUNK_DATA32 pImageTrunkData32 = NULL;
    DWORD OriginalFirstThunk = 0;
    PIMAGE_IMPORT_BY_NAME pImportName = NULL;

    appendTextEdit("");
    while(pImportDescriptor->Name != 0x0 && pImportDescriptor->OriginalFirstThunk != 0x0 && pImportDescriptor->FirstThunk != 0x0)
    {
        memset(buf, 0, 1024);
        RVA2FOA(fileBuffer.pBuffer, pImportDescriptor->Name, &FOA);
        sprintf(buf, "DLL名称：%s", fileBuffer.pBuffer + FOA);
        appendTextEdit(QString(buf));

        //解析函数
        appendTextEdit("导出编号       函数名称");
        RVA2FOA(fileBuffer.pBuffer, pImportDescriptor->OriginalFirstThunk, &FOA);
        pImageTrunkData32 = (PIMAGE_THUNK_DATA32)(fileBuffer.pBuffer + FOA);
        OriginalFirstThunk = *((DWORD *)pImageTrunkData32);
        while(OriginalFirstThunk != 0){
            if(OriginalFirstThunk & 0x80000000){
                //按符号导出
                HIT = OriginalFirstThunk & 0x7FFFFFFF;
                memset(buf, 0, 1024);
                sprintf(buf, "%04x           -", HIT);
                appendTextEdit(QString(buf));
            }else{
                //按函数名导出
                RVA2FOA(fileBuffer.pBuffer, OriginalFirstThunk, &FOA);
                pImportName = (PIMAGE_IMPORT_BY_NAME)(fileBuffer.pBuffer + FOA);
                memset(buf, 0, 1024);
                sprintf(buf, "%04x           %s", pImportName->Hint, &(pImportName->Name));
                appendTextEdit(QString(buf));
            }
            pImageTrunkData32++;
            OriginalFirstThunk = *((DWORD *)pImageTrunkData32);
        }
        appendTextEdit("");
        pImportDescriptor++;
    }

}

void MainWindow::on_actionBoundImportTable_triggered()
{
    if(fileBuffer.pBuffer == NULL || fileBuffer.size == 0){
        QMessageBox::information(this, APP_NAME, "还没有打开任何PE文件！");
        return;
    }

    if(fileType != FILE_TYPE_PE){
        QMessageBox::information(this, APP_NAME, "非法的PE文件！");
        return;
    }

    appendTextEdit("---------------------------------------绑定导入表---------------------------------------");

    char buf[1024] = {0};
    sprintf(buf,"绑定导入表在可选PE头数据目录的索引11项，pOptionHeader->DataDirectory[11].VirtualAddress=%08x",pOptionHeader->DataDirectory[11].VirtualAddress);
    appendTextEdit(QString(buf));

    if(pOptionHeader->DataDirectory[11].VirtualAddress == 0x0){
        appendTextEdit("ERROR:该PE文件无绑定导入表");
        return;
    }

    DWORD FOA;
    RVA2FOA(fileBuffer.pBuffer, pOptionHeader->DataDirectory[11].VirtualAddress, &FOA);
    LOG_DEBUG("FOA=%x", FOA);
    PIMAGE_BOUND_IMPORT_DESCRIPTOR pBoundImportDescriptor = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)(fileBuffer.pBuffer + FOA);
    PIMAGE_BOUND_IMPORT_DESCRIPTOR pCurrentBoundImportDescriptor = pBoundImportDescriptor; //pBoundImportDescriptor不能动
    PIMAGE_BOUND_FORWARDER_REF pBoundForwarderRef = NULL;
    DWORD ref = 0;

     //绑定导入表在头中，而不再节中
    appendTextEdit("");
    while(pCurrentBoundImportDescriptor->TimeDateStamp)
    {
        memset(buf, 0, 1024);
        ref = pCurrentBoundImportDescriptor->NumberOfModuleForwarderRefs;
        sprintf(buf, "DLL名称：%s ，依赖dll个数：%x", (char *)(pCurrentBoundImportDescriptor->OffsetModuleName + (DWORD)pBoundImportDescriptor), ref);
        appendTextEdit(QString(buf));
        if(ref > 0){
            pBoundForwarderRef = (PIMAGE_BOUND_FORWARDER_REF) ((DWORD) pCurrentBoundImportDescriptor + sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR));
            for(int i=0; i<ref; i++)
            {
                memset(buf, 0, 1024);
                sprintf(buf, "     依赖DLL名称：%s ", (char *)((DWORD)((pBoundForwarderRef + i)->OffsetModuleName) + (DWORD)pBoundImportDescriptor));
                appendTextEdit(QString(buf));
            }
            pCurrentBoundImportDescriptor = pCurrentBoundImportDescriptor + (ref+1);
        }else{
            pCurrentBoundImportDescriptor++;
        }
    }
}

void MainWindow::on_actionResourceTable_triggered()
{
    if(fileBuffer.pBuffer == NULL || fileBuffer.size == 0){
        QMessageBox::information(this, APP_NAME, "还没有打开任何PE文件！");
        return;
    }

    if(fileType != FILE_TYPE_PE){
        QMessageBox::information(this, APP_NAME, "非法的PE文件！");
        return;
    }

    appendTextEdit("---------------------------------------资源表---------------------------------------");

    char buf[1024] = {0};
    sprintf(buf,"资源表在可选PE头数据目录的索引2项，pOptionHeader->DataDirectory[2].VirtualAddress=%08x",pOptionHeader->DataDirectory[2].VirtualAddress);
    appendTextEdit(QString(buf));

    if(pOptionHeader->DataDirectory[2].VirtualAddress == 0x0){
        appendTextEdit("ERROR:该PE文件无资源表");
        return;
    }

    DWORD FOA;
    RVA2FOA(fileBuffer.pBuffer, pOptionHeader->DataDirectory[2].VirtualAddress, &FOA);
    LOG_DEBUG("FOA=%x", FOA);

    PIMAGE_RESOURCE_DIRECTORY pResourceDirectory = (PIMAGE_RESOURCE_DIRECTORY)(fileBuffer.pBuffer + FOA);
    memset(buf, 0, 1024);
    sprintf(buf, "     以名称命名的资源数量：%x ", pResourceDirectory->NumberOfNamedEntries);
    appendTextEdit(QString(buf));
    memset(buf, 0, 1024);
    sprintf(buf, "      以ID命名的资源数量：%x ", pResourceDirectory->NumberOfIdEntries);
    appendTextEdit(QString(buf));

    static char* szResName[0x11] ={ 0, "鼠标指针", "位图", "图标", "菜单", "对话框", "字符串列表", "字体目录", "字体",
                                    "快捷键", "非格式化资源", "消息列表","鼠标指针组", "zz", "图标组", "xx", "版本信息"};
    size_t NumEntry = pResourceDirectory->NumberOfIdEntries + pResourceDirectory->NumberOfNamedEntries;
    PIMAGE_RESOURCE_DIRECTORY_ENTRY pResEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)((DWORD)pResourceDirectory + sizeof(IMAGE_RESOURCE_DIRECTORY));

    appendTextEdit("\n资源解析：");
    //获取第一层
    for (size_t i = 0; i < NumEntry; i++)
    {
        //判断最高位
        if (!pResEntry[i].NameIsString)
        {
            //最高位0
            if (pResEntry[i].Id < 0x11) //如果id大于0x11就是自己写的ID资源
            {
                memset(buf, 0, 1024);
                sprintf(buf, "    -->资源类型ID:%2x    %s", pResEntry[i].Id, szResName[pResEntry[i].Id]);
                appendTextEdit(QString(buf));
            }
            else{
                memset(buf, 0, 1024);
                sprintf(buf, "    -->资源类型ID:%2x", pResEntry[i].Id);
                appendTextEdit(QString(buf));
            }
        }
        else
        {
            //最高位1，那么这个第一个联合体的最高位为1，也就是说NameIsString为1，如果资源是未知的，这种资源属于字符串作为资源标识， Name就不会起作用了，NameOffset会指向IMAGE_RESOUCE_DIR_STRING_U的位置
            //先获取偏移
            PIMAGE_RESOURCE_DIR_STRING_U pStringRes = (PIMAGE_RESOURCE_DIR_STRING_U)((DWORD)pResourceDirectory + pResEntry[i].NameOffset);
            //定义一个用来接收自定义字符串的宽数组然后直接复制
            WCHAR szStr[MAX_PATH] = { 0 };
            char chStr[MAX_PATH] = { 0 };
            memcpy_s(szStr, MAX_PATH, pStringRes->NameString, pStringRes->Length*sizeof(WCHAR));
            memset(buf, 0, 1024);
            Wchar2Char(szStr, chStr, MAX_PATH);
            sprintf(buf, "    -->资源名称：%s", chStr);
            appendTextEdit(QString(buf));
        }

        //第二层
        if (pResEntry[i].DataIsDirectory)
        {
            //LOG_DEBUG("第二层目录偏移是：%p\n", pResEntry[i].OffsetToDirectory);
            //定义二层目录的目录头 以及entry
            PIMAGE_RESOURCE_DIRECTORY pResDirectory2 = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)pResourceDirectory + pResEntry[i].OffsetToDirectory);
            PIMAGE_RESOURCE_DIRECTORY_ENTRY pResEntry2 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResDirectory2 + 1);
            //获得ENtry个数
            size_t NumEntry2 = pResDirectory2->NumberOfIdEntries + pResDirectory2->NumberOfNamedEntries;

            for (DWORD i = 0; i < NumEntry2; i++)
            {
                if (!pResEntry2[i].NameIsString)
                {
                    memset(buf, 0, 1024);
                    sprintf(buf, "        -->资源标识ID:%2x", pResEntry2[i].Id);
                    appendTextEdit(QString(buf));
                }
                else
                {
                    // 显示资源字符串,NameOffset为相对资源的文件偏移,字符串偏移为 资源基地址+NameOffset
                    PIMAGE_RESOURCE_DIR_STRING_U pstcString = (PIMAGE_RESOURCE_DIR_STRING_U)((DWORD)pResourceDirectory + pResEntry2[i].NameOffset);
                    WCHAR szStr[MAX_PATH] = { 0 };
                    char chStr[MAX_PATH] = { 0 };
                    memcpy(szStr,pstcString->NameString,pstcString->Length*sizeof(WCHAR));
                    Wchar2Char(szStr, chStr, MAX_PATH);
                    sprintf(buf, "        -->资源名称：%s", chStr);
                    appendTextEdit(buf);
                }

                //第三层
                PIMAGE_RESOURCE_DIRECTORY pResourceDirectory3 = (PIMAGE_RESOURCE_DIRECTORY)((DWORD)pResourceDirectory + pResEntry2[i].OffsetToDirectory);
                //LOG_DEBUG("第三层目录:%d\n", pResourceDirectory3->NumberOfIdEntries);
                PIMAGE_RESOURCE_DIRECTORY_ENTRY pResEntry3 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResourceDirectory3 + 1);
                if (!pResEntry3[i].DataIsDirectory)
                {
                    // 取数据偏移,显示数据
                    PIMAGE_RESOURCE_DATA_ENTRY pResData = (PIMAGE_RESOURCE_DATA_ENTRY)((DWORD)pResourceDirectory + pResEntry3->OffsetToData);
                    memset(buf, 0, 1024);
                    sprintf(buf, "           -->数据RVA:%8x  数据大小:%08x,", pResData->OffsetToData,pResData->Size);
                    appendTextEdit(QString(buf));
                }
            }
        }

        appendTextEdit("");
    }
}

///////////////////////////////////////////////// ELF File Parser ///////////////////////////////////////////
void MainWindow::on_actionParseElfHeader_triggered()
{
    if(fileBuffer.pBuffer == NULL || fileBuffer.size == 0){
        QMessageBox::information(this, APP_NAME, "还没有打开任何ELF文件！");
        return;
    }

    if(fileType != FILE_TYPE_ELF){
        QMessageBox::information(this, APP_NAME, "非法的ELF文件！");
        return;
    }

    appendTextEdit("---------------------------------------ELF头---------------------------------------");
    char buf[1024] = {0};
    sprintf(buf, "                        e_ident:                    //[*]ELF的一些标识信息");
    appendTextEdit(QString(buf));

    appendTextEdit(QString(""));
    memset(buf, 0, 1024);
    sprintf(buf, "                                 magic:%08x                //.ELF", *((DWORD *)pElf32_Ehdr->e_ident));
    appendTextEdit(QString(buf));
    memset(buf, 0, 1024);
    sprintf(buf, "                                 class:%02x                      //文件类, 三种取值：ELFCLASSNONE（0）非法类别；ELFCLASS32（1）32位目标；ELFCLASS64（2）64位目标", pElf32_Ehdr->e_ident[4]);
    appendTextEdit(QString(buf));
    memset(buf, 0, 1024);
    sprintf(buf, "                               version:%02x                      //文件版本", pElf32_Ehdr->e_ident[6]);
    appendTextEdit(QString(buf));
    memset(buf, 0, 1024);
    sprintf(buf, "                                OS/ABI:%02x                      //OS/ABI, 0: Unix - System V", pElf32_Ehdr->e_ident[7]);
    appendTextEdit(QString(buf));
    memset(buf, 0, 1024);
    sprintf(buf, "                           ABI version:%02x                      //ABI版本", pElf32_Ehdr->e_ident[8]);
    appendTextEdit(QString(buf));
    memset(buf, 0, 1024);
    sprintf(buf, "                                EI_PAD:00 00 00 00 00 00       //补齐字节开始处，默认为0,保留字");
    appendTextEdit(QString(buf));
    memset(buf, 0, 1024);
    sprintf(buf, "                          e_ident size:%02x                      //ABI版本", pElf32_Ehdr->e_ident[15]);
    appendTextEdit(QString(buf));

    if(pElf64_Ehdr != NULL){
        // 64bit elf file
        appendTextEdit(QString(""));
        memset(buf, 0, 1024);
        sprintf(buf, "                         e_type:%04x                 //表示elf文件的类型,取值：0 未知目标文件格式,1 可重定位文件, 2 可执行文件, 3 共享目标文件, 4 Core 文件（转储格式）, 0xff00 特定处理器文件, 0xffff 特定处理器文件, 0xff00~0xffff 特定处理器文件 ", pElf64_Ehdr->e_type);
        appendTextEdit(QString(buf));
        memset(buf, 0, 1024);
        sprintf(buf, "                      e_machine:%04x                 //表示目标体系结构类型", pElf64_Ehdr->e_machine);
        appendTextEdit(QString(buf));
        memset(buf, 0, 1024);
        sprintf(buf, "                      e_version:%08x             //当前版本，0为非法版本，1为当前版本", pElf64_Ehdr->e_version);
        appendTextEdit(QString(buf));
        memset(buf, 0, 1024);
        sprintf(buf, "                        e_entry:%016x     //程序入口地址", pElf64_Ehdr->e_entry);
        appendTextEdit(QString(buf));
        memset(buf, 0, 1024);
        sprintf(buf, "                        e_phoff:%016x     //程序头部表偏移地址", pElf64_Ehdr->e_phoff);
        appendTextEdit(QString(buf));
        memset(buf, 0, 1024);
        sprintf(buf, "                        e_shoff:%016x     //节区头部表偏移地址", pElf64_Ehdr->e_shoff);
        appendTextEdit(QString(buf));
        memset(buf, 0, 1024);
        sprintf(buf, "                        e_flags:%08x             //保存与文件相关的，特定于处理器的标志", pElf64_Ehdr->e_flags);
        appendTextEdit(QString(buf));
        memset(buf, 0, 1024);
        sprintf(buf, "                       e_ehsize:%04x                 //保存与文件相关的，特定于处理器的标志", pElf64_Ehdr->e_ehsize);
        appendTextEdit(QString(buf));
        memset(buf, 0, 1024);
        sprintf(buf, "                    e_phentsize:%04x                 //每个程序头部表的大小", pElf64_Ehdr->e_phentsize);
        appendTextEdit(QString(buf));
        memset(buf, 0, 1024);
        sprintf(buf, "                        e_phnum:%04x                 //程序头部表的数量", pElf64_Ehdr->e_phnum);
        appendTextEdit(QString(buf));
        memset(buf, 0, 1024);
        sprintf(buf, "                    e_shentsize:%04x                 //每个节区头部表的大小", pElf64_Ehdr->e_shentsize);
        appendTextEdit(QString(buf));
        memset(buf, 0, 1024);
        sprintf(buf, "                        e_shnum:%04x                 //节区头部表的数量", pElf64_Ehdr->e_shnum);
        appendTextEdit(QString(buf));
        memset(buf, 0, 1024);
        sprintf(buf, "                     e_shstrndx:%04x                 //节区字符串表位置", pElf64_Ehdr->e_shstrndx);
        appendTextEdit(QString(buf));
    }else{
        // 32 bit elf
        appendTextEdit(QString(""));
        memset(buf, 0, 1024);
        sprintf(buf, "                         e_type:%04x                 //表示elf文件的类型,取值：0 未知目标文件格式,1 可重定位文件, 2 可执行文件, 3 共享目标文件, 4 Core 文件（转储格式）, 0xff00 特定处理器文件, 0xffff 特定处理器文件, 0xff00~0xffff 特定处理器文件 ", pElf32_Ehdr->e_type);
        appendTextEdit(QString(buf));
        memset(buf, 0, 1024);
        sprintf(buf, "                      e_machine:%04x                 //表示目标体系结构类型", pElf32_Ehdr->e_machine);
        appendTextEdit(QString(buf));
        memset(buf, 0, 1024);
        sprintf(buf, "                      e_version:%08x             //当前版本，0为非法版本，1为当前版本", pElf32_Ehdr->e_version);
        appendTextEdit(QString(buf));
        memset(buf, 0, 1024);
        sprintf(buf, "                        e_entry:%08x             //程序入口地址", pElf32_Ehdr->e_entry);
        appendTextEdit(QString(buf));
        memset(buf, 0, 1024);
        sprintf(buf, "                        e_phoff:%08x             //程序头部表偏移地址", pElf32_Ehdr->e_phoff);
        appendTextEdit(QString(buf));
        memset(buf, 0, 1024);
        sprintf(buf, "                        e_shoff:%08x             //节区头部表偏移地址", pElf32_Ehdr->e_shoff);
        appendTextEdit(QString(buf));
        memset(buf, 0, 1024);
        sprintf(buf, "                        e_flags:%08x             //保存与文件相关的，特定于处理器的标志", pElf32_Ehdr->e_flags);
        appendTextEdit(QString(buf));
        memset(buf, 0, 1024);
        sprintf(buf, "                       e_ehsize:%04x                 //保存与文件相关的，特定于处理器的标志", pElf32_Ehdr->e_ehsize);
        appendTextEdit(QString(buf));
        memset(buf, 0, 1024);
        sprintf(buf, "                    e_phentsize:%04x                 //每个程序头部表的大小", pElf32_Ehdr->e_phentsize);
        appendTextEdit(QString(buf));
        memset(buf, 0, 1024);
        sprintf(buf, "                        e_phnum:%04x                 //程序头部表的数量", pElf32_Ehdr->e_phnum);
        appendTextEdit(QString(buf));
        memset(buf, 0, 1024);
        sprintf(buf, "                    e_shentsize:%04x                 //每个节区头部表的大小", pElf32_Ehdr->e_shentsize);
        appendTextEdit(QString(buf));
        memset(buf, 0, 1024);
        sprintf(buf, "                        e_shnum:%04x                 //节区头部表的数量", pElf32_Ehdr->e_shnum);
        appendTextEdit(QString(buf));
        memset(buf, 0, 1024);
        sprintf(buf, "                     e_shstrndx:%04x                 //节区字符串表位置", pElf32_Ehdr->e_shstrndx);
        appendTextEdit(QString(buf));
    }
}

void MainWindow::on_actionParseProgramHeader_triggered()
{
    if(fileBuffer.pBuffer == NULL || fileBuffer.size == 0){
        QMessageBox::information(this, APP_NAME, "还没有打开任何ELF文件！");
        return;
    }

    if(fileType != FILE_TYPE_ELF){
        QMessageBox::information(this, APP_NAME, "非法的ELF文件！");
        return;
    }

}

void MainWindow::on_actionParseSectionTable_triggered()
{
    int size = 0;
    if(fileBuffer.pBuffer == NULL || fileBuffer.size == 0){
        QMessageBox::information(this, APP_NAME, "还没有打开任何ELF文件！");
        return;
    }

    if(fileType != FILE_TYPE_ELF){
        QMessageBox::information(this, APP_NAME, "非法的ELF文件！");
        return;
    }

    if(pElf64_Ehdr != NULL){
        size = pElf64_Ehdr->e_shnum;
    }else{
        size = pElf32_Ehdr->e_shnum;
    }

    char buf[1024] = {0};
    sprintf(buf, "---------------------------------------Sections[共%d个]---------------------------------------", size);
    appendTextEdit(QString(buf));
    appendTextEdit(QString("sh_type意义："));
    std::map<unsigned int, std::string> sh_type;
    sh_type.insert(std::pair<unsigned int, std::string>(SHT_NULL, "此值标志节区头部是非活动的，没有对应的节区。此节区头部中的其他成员取值无意义"));
    sh_type.insert(std::pair<unsigned int, std::string>(SHT_PROGBITS, "此节区包含程序定义的信息，其格式和含义都由程序来解释"));
    sh_type.insert(std::pair<unsigned int, std::string>(SHT_SYMTAB, "此节区包含一个符号表。目前目标文件对每种类型的节区都只能包含一个，不过这个限制将来可能发生变化。一般，SHT_SYMTAB 节区提供用于链接编辑（指 ld 而言）的符号，尽管也可用来实现动态链接"));
    sh_type.insert(std::pair<unsigned int, std::string>(SHT_STRTAB, "此节区包含字符串表。目标文件可能包含多个字符串表节区"));
    sh_type.insert(std::pair<unsigned int, std::string>(SHT_RELA, "此节区包含重定位表项，其中可能会有补齐内容（addend），例如 32 位目标文件中的 Elf32_Rela 类型。目标文件可能拥有多个重定位节区"));
    sh_type.insert(std::pair<unsigned int, std::string>(SHT_HASH, "此节区包含符号哈希表。所有参与动态链接的目标都必须包含一个符号哈希表。目前，一个目标文件只能包含一个哈希表，不过此限制将来可能会解除"));
    sh_type.insert(std::pair<unsigned int, std::string>(SHT_DYNAMIC, "此节区包含动态链接的信息。目前一个目标文件中只能包含一个动态节区，将来可能会取消这一限制"));
    sh_type.insert(std::pair<unsigned int, std::string>(SHT_NOTE	, "此节区包含以某种方式来标记文件的信息"));
    sh_type.insert(std::pair<unsigned int, std::string>(SHT_NOBITS, "这种类型的节区不占用文件中的空间，其他方面和SHT_PROGBITS 相似。尽管此节区不包含任何字节，成员sh_offset 中还是会包含概念性的文件偏移"));
    sh_type.insert(std::pair<unsigned int, std::string>(SHT_REL, "此节区包含重定位表项，其中没有补齐（addends），例如 32 位目标文件中的 Elf32_rel 类型。目标文件中可以拥有多个重定位节区"));
    sh_type.insert(std::pair<unsigned int, std::string>(SHT_SHLIB, "此节区被保留，不过其语义是未规定的。包含此类型节区的程序与 ABI 不兼容"));
    sh_type.insert(std::pair<unsigned int, std::string>(SHT_DYNSYM, "作为一个完整的符号表，它可能包含很多对动态链接而言不必要的符号。因此，目标文件也可以包含一个 SHT_DYNSYM 节区，其中保存动态链接符号的一个最小集合，以节省空间"));
    sh_type.insert(std::pair<unsigned int, std::string>(SHT_INIT_ARRAY, "Array of constructors"));
    sh_type.insert(std::pair<unsigned int, std::string>(SHT_FINI_ARRAY, "Array of destructors"));
    sh_type.insert(std::pair<unsigned int, std::string>(SHT_PREINIT_ARRAY, "Array of pre-constructors"));
    sh_type.insert(std::pair<unsigned int, std::string>(SHT_GROUP, "Section group"));
    sh_type.insert(std::pair<unsigned int, std::string>(SHT_LOPROC, "SHT_SYMTAB_SHNDX"));
    sh_type.insert(std::pair<unsigned int, std::string>(SHT_NUM, "Number of defined types"));
    sh_type.insert(std::pair<unsigned int, std::string>(SHT_LOOS, "Start OS-specific"));
    sh_type.insert(std::pair<unsigned int, std::string>(SHT_GNU_ATTRIBUTES, "Object attributes"));
    sh_type.insert(std::pair<unsigned int, std::string>(SHT_GNU_HASH, "GNU-style hash table"));
    sh_type.insert(std::pair<unsigned int, std::string>(SHT_GNU_LIBLIST, "relink library list"));
    sh_type.insert(std::pair<unsigned int, std::string>(SHT_CHECKSUM, "hecksum for DSO content"));
    sh_type.insert(std::pair<unsigned int, std::string>(SHT_LOSUNW, "Sun-specific low bound"));
    sh_type.insert(std::pair<unsigned int, std::string>(SHT_SUNW_COMDAT, "Sun-specific low bound"));
    sh_type.insert(std::pair<unsigned int, std::string>(SHT_SUNW_syminfo, "Sun-specific low bound"));
    sh_type.insert(std::pair<unsigned int, std::string>(SHT_GNU_verdef, "Version definition section"));
    sh_type.insert(std::pair<unsigned int, std::string>(SHT_GNU_verneed, "Version needs section"));
    sh_type.insert(std::pair<unsigned int, std::string>(SHT_GNU_versym, "Version symbol table"));
    sh_type.insert(std::pair<unsigned int, std::string>(SHT_LOPROC, "这一段（包括两个边界），是保留给处理器专用语义的"));
    sh_type.insert(std::pair<unsigned int, std::string>(SHT_HIPROC, "这一段（包括两个边界），是保留给处理器专用语义的"));
    sh_type.insert(std::pair<unsigned int, std::string>(SHT_LOUSER, "此值给出保留给应用程序的索引下界"));
    sh_type.insert(std::pair<unsigned int, std::string>(SHT_HIUSER, "此值给出保留给应用程序的索引上界"));

    if(pElf64_Shdr != NULL){
        for(int i=0; i<size; i++){
            Elf64_Shdr *pShdr = (Elf64_Shdr *)((unsigned char *)pElf64_Shdr + sizeof(Elf64_Shdr) * i);
            memset(buf, 0, 1024);
            sprintf(buf, "                               sh_name:%08x                //节区名", pShdr->sh_name);
            appendTextEdit(QString(buf));
            memset(buf, 0, 1024);
            if(sh_type.find(pShdr->sh_type)  != sh_type.end()){
                sprintf(buf, "                               sh_type:%08x                //为节区类型，%x表示：%s", pShdr->sh_type,pShdr->sh_type,sh_type[pShdr->sh_type].c_str());
                appendTextEdit(QString(buf));
            }else{
                sprintf(buf, "                               sh_type:%08x                //为节区类型", pShdr->sh_type);
                appendTextEdit(QString(buf));
            }
            memset(buf, 0, 1024);
            sprintf(buf, "                              sh_flags:%016x        //节区标志(多个标志位与运算结果，详情查elf.h)", pShdr->sh_flags);
            appendTextEdit(QString(buf));
            memset(buf, 0, 1024);
            sprintf(buf, "                               sh_addr:%016x        //如果节区将出现在进程的内存映像中，此成员给出节区的第一个字节应处的位置。否则，此字段为 0", pShdr->sh_addr);
            appendTextEdit(QString(buf));
            memset(buf, 0, 1024);
            sprintf(buf, "                               sh_size:%08x                //此成员给出节区的长度（字节数）", pShdr->sh_size);
            appendTextEdit(QString(buf));
            memset(buf, 0, 1024);
            sprintf(buf, "                               sh_link:%08x                //此成员给出节区头部表索引链接。其具体的解释依赖于节区类型", pShdr->sh_link);
            appendTextEdit(QString(buf));
            memset(buf, 0, 1024);
            sprintf(buf, "                               sh_info:%08x                //此成员给出附加信息，其解释依赖于节区类型", pShdr->sh_info);
            appendTextEdit(QString(buf));
            memset(buf, 0, 1024);
            sprintf(buf, "                          sh_addralign:%08x                //某些节区带有地址对齐约束", pShdr->sh_addralign);
            appendTextEdit(QString(buf));
            memset(buf, 0, 1024);
            sprintf(buf, "                            sh_entsize:%08x                //某些节区中包含固定大小的项目，如符号表。对于这类节区，此成员给出每个表项的长度字节数", pShdr->sh_entsize);
            appendTextEdit(QString(buf));

            appendTextEdit("");
        }
    }else{
        for(int i=0; i<size; i++){
            Elf32_Shdr *pShdr = (Elf32_Shdr *)((unsigned char *)pElf32_Shdr + sizeof(Elf32_Shdr) * i);
            memset(buf, 0, 1024);
            sprintf(buf, "                               sh_name:%08x                //节区名", pShdr->sh_name);
            appendTextEdit(QString(buf));
            memset(buf, 0, 1024);
            if(sh_type.find(pShdr->sh_type)  != sh_type.end()){
                sprintf(buf, "                               sh_type:%08x                //为节区类型，%x表示：%s", pShdr->sh_type,pShdr->sh_type,sh_type[pShdr->sh_type].c_str());
                appendTextEdit(QString(buf));
            }else{
                sprintf(buf, "                               sh_type:%08x                //为节区类型", pShdr->sh_type);
                appendTextEdit(QString(buf));
            }
            memset(buf, 0, 1024);
            sprintf(buf, "                              sh_flags:%08x                //节区标志(多个标志位与运算结果，详情查elf.h)", pShdr->sh_flags);
            appendTextEdit(QString(buf));
            memset(buf, 0, 1024);
            sprintf(buf, "                               sh_addr:%08x                //如果节区将出现在进程的内存映像中，此成员给出节区的第一个字节应处的位置。否则，此字段为 0", pShdr->sh_addr);
            appendTextEdit(QString(buf));
            memset(buf, 0, 1024);
            sprintf(buf, "                               sh_size:%08x                //此成员给出节区的长度（字节数）", pShdr->sh_size);
            appendTextEdit(QString(buf));
            memset(buf, 0, 1024);
            sprintf(buf, "                               sh_link:%08x                //此成员给出节区头部表索引链接。其具体的解释依赖于节区类型", pShdr->sh_link);
            appendTextEdit(QString(buf));
            memset(buf, 0, 1024);
            sprintf(buf, "                               sh_info:%08x                //此成员给出附加信息，其解释依赖于节区类型", pShdr->sh_info);
            appendTextEdit(QString(buf));
            memset(buf, 0, 1024);
            sprintf(buf, "                          sh_addralign:%08x                //某些节区带有地址对齐约束", pShdr->sh_addralign);
            appendTextEdit(QString(buf));
            memset(buf, 0, 1024);
            sprintf(buf, "                            sh_entsize:%08x                //某些节区中包含固定大小的项目，如符号表。对于这类节区，此成员给出每个表项的长度字节数", pShdr->sh_entsize);
            appendTextEdit(QString(buf));

            appendTextEdit("");
        }
    }
}

void MainWindow::on_actionParseSections_triggered()
{
    if(fileBuffer.pBuffer == NULL || fileBuffer.size == 0){
        QMessageBox::information(this, APP_NAME, "还没有打开任何ELF文件！");
        return;
    }

    if(fileType != FILE_TYPE_ELF){
        QMessageBox::information(this, APP_NAME, "非法的ELF文件！");
        return;
    }

}

void MainWindow::on_actionElfDetailParser_triggered()
{
    if(fileBuffer.pBuffer == NULL || fileBuffer.size == 0){
        QMessageBox::information(this, APP_NAME, "还没有打开任何ELF文件！");
        return;
    }

    if(fileType != FILE_TYPE_ELF){
        QMessageBox::information(this, APP_NAME, "非法的ELF文件！");
        return;
    }

    on_actionParseElfHeader_triggered();
    on_actionParseSectionTable_triggered();
}
