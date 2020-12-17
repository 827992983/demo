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
    setFixedSize(1000, 600);
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
    if(fileBuffer.pBuffer != NULL){
        free(fileBuffer.pBuffer);
        fileBuffer.pBuffer = NULL;
        fileBuffer.size = 0;
    }

    pDosHeader = NULL;
    pNTHeader = NULL;
    pPEHeader = NULL;
    pOptionHeader = NULL;
    pSectionHeader = NULL;

    if(pOutputResult != NULL) delete pOutputResult;
#ifdef DEBUG
    delete btnTest;
#endif
    delete ui;
}

void MainWindow::appendTextEdit(QString data)
{
    QString tmp = ui->textEdit->toPlainText();
    tmp += data;
    tmp += "\n";
    ui->textEdit->setText(tmp);
    curLine++;
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
        free(fileBuffer.pBuffer);
        fileBuffer.pBuffer = NULL;
        fileBuffer.size = 0;
        ui->textEdit->setText("");
    }
    LoadFile(fileName.toStdString().c_str(), &fileBuffer.pBuffer, &fileBuffer.size);
    LOG_INFO("Load File Size=%d",fileBuffer.size);
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
    pDosHeader = (PIMAGE_DOS_HEADER)fileBuffer.pBuffer;
    if(CheckDosHeaderMagic(pDosHeader->e_magic) < 0){
        QMessageBox::information(this, APP_NAME, "这不是PE格式文件！");
        return;
    }
    appendTextEdit("------------------------------DOS头------------------------------");
    char buf[1024] = {0};
    sprintf(buf, " e_magic:%8x                //MZ，DOS头的幻数", pDosHeader->e_magic);
    appendTextEdit(QString(buf));
    memset(buf, 0, 1024);
    sprintf(buf, "e_lfanew:%8x                //PE头相对于文件的偏移，用于定位PE文件（具体值会由于编译器不同，具体值不一定）", pDosHeader->e_lfanew);
    appendTextEdit(QString(buf));
}

void MainWindow::on_actionParsePeHeader_triggered()
{

}

void MainWindow::on_actionParseOptionalHeader_triggered()
{

}

void MainWindow::on_actionClearScreen_triggered()
{
    ui->textEdit->setText("");
}
