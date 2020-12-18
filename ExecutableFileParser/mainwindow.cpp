#include "mainwindow.h"
#include "ui_mainwindow.h"

#include "logger.h"
#include "pe_parser.h"
#include <QMessageBox>
#include <QFileDialog>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    setWindowTitle(APP_NAME);
    setWindowFlags(Qt::WindowCloseButtonHint);//只显示关闭按钮
    setFixedSize(1200, 800);
    ui->textEdit->setReadOnly(true);
#ifdef Q_OS_WIN32
    ui->labelStatus->setText("日志：C:/Windows/Temp/ExecutableFileParser.log");
#endif

#ifdef Q_OS_LINUX
    ui->labelStatus->setText("日志：/tmp/ExecutableFileParser.log");
#endif
    ui->statusBar->addWidget(ui->labelStatus);

    pOutputResult = new QString[512];
    curLine = 0;
    fileBuffer.pBuffer = NULL;
    fileBuffer.size = 0;

    pDosHeader = NULL;
    pNTHeader = NULL;
    pPEHeader = NULL;
    pOptionHeader = NULL;
    pSectionHeader = NULL;

#ifdef DEBUG
    btnTest = new QPushButton(this);
    btnTest->setText("测试");
    ui->mainToolBar->addWidget(btnTest);
    //connect(btnTest,&QPushButton::clicked,this, on_btnTest_clicked);
    connect(btnTest, SIGNAL(clicked()), this, SLOT(on_btnTest_clicked()));
#endif
    connect(ui->actionAbout, &QAction::triggered, this, on_actionAbout_clicked);
    connect(ui->actionOpen, &QAction::triggered, this, on_actionOpen_clicked);
}

MainWindow::~MainWindow()
{
    cleanFileBuffer();

    if(pOutputResult != NULL) delete pOutputResult;
#ifdef DEBUG
    delete btnTest;
#endif
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
        ui->textEdit->setText("");
    }
}

#ifdef DEBUG
void MainWindow::on_btnTest_clicked()
{
    appendTextEdit("OK");
    if(fileName.size()<1){
        return;
    }
    PrintNTHeaders(fileName.toStdString().c_str());
}
#endif

void MainWindow::on_actionOpen_clicked()
{
    fileName = QFileDialog::getOpenFileName(this, tr("文件对话框！"), "", tr("PE(*exe *dll *sys);;""ELF(*so *out *);;""所有文件(*)"));
    if(fileName.size() < 1){
        return;
    }

    LOG_INFO("Select File Name=%s",fileName.toStdString().c_str());
    if(fileBuffer.pBuffer != NULL){
        cleanFileBuffer();
    }
    LoadFile(fileName.toStdString().c_str(), &fileBuffer.pBuffer, &fileBuffer.size);
    LOG_INFO("Load File Size=%d",fileBuffer.size);

    pDosHeader = (PIMAGE_DOS_HEADER)fileBuffer.pBuffer;
    if(CheckDosHeaderMagic(pDosHeader->e_magic) < 0){
        QMessageBox::information(this, APP_NAME, "DOS头解析错误，这不是PE格式文件！");
        cleanFileBuffer();
        return;
    }

    pNTHeader = (PIMAGE_NT_HEADERS)((unsigned char *)fileBuffer.pBuffer+pDosHeader->e_lfanew);
    if(CheckPeHeaderMagic(pNTHeader->Signature) < 0){
        QMessageBox::information(this, APP_NAME, "NT头解析错误，这不是PE格式文件！");
        cleanFileBuffer();
        return;
    }
    pPEHeader = (PIMAGE_FILE_HEADER)(((unsigned char *)pNTHeader) + 4);
    pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((unsigned char *)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
    pSectionHeader = (PIMAGE_SECTION_HEADER)((unsigned char *)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
}

void MainWindow::on_actionAbout_clicked()
{
    QMessageBox::information(this, APP_NAME, "可执行文件解析器（支持PE/ELF格式）\n版本：V1.0");
}

void MainWindow::on_actionParseDosHeader_triggered()
{
    if(fileBuffer.pBuffer == NULL || fileBuffer.size == 0){
        QMessageBox::information(this, APP_NAME, "还没有打开任何PE文件！");
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
    sprintf(buf, "               NumberOfSections:%04x                //[*]节（Section）数，PE文件时候分节的，即：PE文件中存在的节的总数,如果要新增节或者合并节 就要修改这个值.", pPEHeader->NumberOfSections);
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

}

void MainWindow::on_actionParseOptionalHeader_triggered()
{
    if(fileBuffer.pBuffer == NULL || fileBuffer.size == 0){
        QMessageBox::information(this, APP_NAME, "还没有打开任何PE文件！");
        return;
    }

    appendTextEdit("---------------------------------------可选PE头[带[*]的是重点]---------------------------------------");
    char buf[1024] = {0};
    sprintf(buf, "                          Magic:%04x                //[*]标志字(幻数),常值为010Bh.用来说明文件是ROM映像,还是普通可执行的映像，说明文件类型：10B 32位下的PE文件，20B 64位下的PE文件", pOptionHeader->Magic);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, "             MajorLinkerVersion:%02x                  //链接器主版本号", pOptionHeader->MajorLinkerVersion);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, "             MinorLinkerVersion:%02x                  //链接器次版本号", pOptionHeader->MinorLinkerVersion);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, "                     SizeOfCode:%08x            //[*]代码段(块)大小,所有Code Section总共的大小(只入不舍),这个值是向上对齐某一个值的整数倍，所有代码节的和，必须是FileAlignment的整数倍 编译器填的  没用", pOptionHeader->SizeOfCode);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, "          SizeOfInitializedData:%08x            //[*]已初始化数据块大小.即在编译时所构成的块的大小(不包括代码段),但这个数据并不太准确，已初始化数据大小的和,必须是FileAlignment的整数倍 编译器填的  没用", pOptionHeader->SizeOfInitializedData);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, "        SizeOfUninitializedData:%08x            //[*]未初始化数据块大小.装载程序要在虚拟地址空间中为这些数据约定空间.未初始化数据通常在.bbs块中，未初始化数据大小的和,必须是FileAlignment的整数倍 编译器填的  没用", pOptionHeader->SizeOfUninitializedData);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, "            AddressOfEntryPoint:%08x            //[*]程序开始执行的入口地址/入口点EP(RVA).这是一个相对虚拟地址，程序入口，ImageBase+AddressOfEntryPoint才是真正的程序入口", pOptionHeader->AddressOfEntryPoint);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, "                     BaseOfCode:%08x            //[*]代码段(块)起始地址，编译器填的   没用", pOptionHeader->BaseOfCode);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, "                     BaseOfData:%08x            //[*]数据段(块)起始地址，编译器填的   没用", pOptionHeader->BaseOfData);
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
    sprintf(buf, "                    SizeOfImage:%08x            //[*]映像大小(映像装入内存后的总尺寸/内存中整个PE映像的尺寸),内存中整个PE文件的映射的尺寸（已经按内存对齐后的大小），可以比实际的值大，但必须是SectionAlignment的整数倍", pOptionHeader->SizeOfImage);
    appendTextEdit(QString(buf));

    memset(buf, 0, 1024);
    sprintf(buf, "                  SizeOfHeaders:%08x            //[*]首部及块表(首部+块表)的大小.],所有头+节表按照文件对齐后的大小，否则加载会出错", pOptionHeader->SizeOfHeaders);
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
    sprintf(buf, "_IMAGE_DATA_DIRECTORY DataDirectory[16];            //数据目录表(16项,每个成员占8字节)", pOptionHeader->DataDirectory);
    appendTextEdit(QString(buf));
}

void MainWindow::on_actionClearScreen_triggered()
{
    ui->textEdit->setText("");
}

void MainWindow::on_actionParseSection_triggered()
{
    int indexSection = 0;
    int sectionNumber = pPEHeader->NumberOfSections;
    PIMAGE_SECTION_HEADER pCurrentSectionHeader = pSectionHeader;;
    appendTextEdit("---------------------------------------块表|区段|节表[带[*]的是重点]---------------------------------------");
    char buf[1024] = {0};
    sprintf(buf, "                      section数:%04x                //IMAGE_FILE_HEADER(PE Header结构体)的NumberOfSections字段", sectionNumber);
    appendTextEdit(QString(buf));
    appendTextEdit("--------------------------------------------------------------------------------------------------------");

    for(indexSection=0; indexSection<sectionNumber; indexSection++){
        memset(buf, 0, 1024);
        sprintf(buf, "                           Name:%s               //[*]名称,长度:8位(16字节)的ASCII码", pCurrentSectionHeader->Name);
        appendTextEdit(QString(buf));

        memset(buf, 0, 1024);
        sprintf(buf, "              (Msic)VirtualSize:%08x            //[*]V(VS),内存中大小(对齐前的长度)，该节在没有对齐之前的真实长度（实际数据大小，对齐解释：如以0x200大小对齐，0x192就会通过补0变成0x200），这个值可能不准确（可能被别人修改）", pCurrentSectionHeader->Misc);
        appendTextEdit(QString(buf));

        memset(buf, 0, 1024);
        sprintf(buf, "                 VirtualAddress:%08x            //[*]V(VO),内存中偏移(该块的RVA)，VirtualAddress 在内存中的偏移 相对于ImageBase偏移(简单理解：离ImageBase多远），在内存中有意义", pCurrentSectionHeader->VirtualAddress);
        appendTextEdit(QString(buf));

        memset(buf, 0, 1024);
        sprintf(buf, "                  SizeOfRawData:%08x            //[*]R(RS),文件中大小(对齐后的长度)，节在文件中对齐后的大小", pCurrentSectionHeader->SizeOfRawData);
        appendTextEdit(QString(buf));

        memset(buf, 0, 1024);
        sprintf(buf, "               PointerToRawData:%08x            //[*]R(RO),文件中偏移.节区在文件中的偏移（对齐后），在文件中", pCurrentSectionHeader->PointerToRawData);
        appendTextEdit(QString(buf));

        memset(buf, 0, 1024);
        sprintf(buf, "           PointerToRelocations:%08x            //[*]在OBJ文件中使用,重定位的偏移.在obj文件中使用 对exe无意义", pCurrentSectionHeader->PointerToRelocations);
        appendTextEdit(QString(buf));

        memset(buf, 0, 1024);
        sprintf(buf, "           PointerToLinenumbers:%08x            //[*]行号表的偏移,提供调试.", pCurrentSectionHeader->PointerToLinenumbers);
        appendTextEdit(QString(buf));

        memset(buf, 0, 1024);
        sprintf(buf, "            NumberOfRelocations:%04x                //[*]在obj文件中使用 重定位项数目 对exe无意义", pCurrentSectionHeader->NumberOfRelocations);
        appendTextEdit(QString(buf));

        memset(buf, 0, 1024);
        sprintf(buf, "            NumberOfLinenumbers:%04x                //[*]行号表中行号的数量 调试的时候使用", pCurrentSectionHeader->NumberOfLinenumbers);
        appendTextEdit(QString(buf));

        memset(buf, 0, 1024);
        sprintf(buf, "                Characteristics:%08x            //[*]节的属性", pCurrentSectionHeader->Characteristics);
        appendTextEdit(QString(buf));

        memset(buf, 0, 1024);
        sprintf(buf, " ");
        appendTextEdit(QString(buf));

        pCurrentSectionHeader = (PIMAGE_SECTION_HEADER)((unsigned char *)(&pCurrentSectionHeader->Characteristics) + sizeof(DWORD));
    }
}
