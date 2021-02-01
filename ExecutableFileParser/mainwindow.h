#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "global_def.h"
#include <QMainWindow>
#include <QPushButton>
#include <windows.h>

namespace Ui {
class MainWindow;
}

typedef struct _FileBuffer{
    unsigned char *pBuffer;
    unsigned int size;
}FileBuffer;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private slots:
#ifdef DEBUG
    void on_btnTest_clicked();
#endif
    void on_actionOpen_clicked();
    void on_actionAbout_clicked();
    void on_actionParseDosHeader_triggered();
    void on_actionParsePeHeader_triggered();
    void on_actionParseOptionalHeader_triggered();
    void on_actionClearScreen_triggered();
    void on_actionParseSection_triggered();
    void on_actionPeDetailParser_triggered();
    void on_actionExportTable_triggered();
    void on_actionBaseRelocationTable_triggered();
    void on_actionImportTable_triggered();
    void on_actionBoundImportTable_triggered();
    void on_actionResourceTable_triggered();

    void on_actionParseElfHeader_triggered();

    void on_actionParseProgramHeader_triggered();

    void on_actionParseSectionTable_triggered();

    void on_actionParseSections_triggered();

    void on_actionElfDetailParser_triggered();

private:
    void appendTextEdit(QString data);
    void cleanFileBuffer();
    int RVA2FOA(PVOID FileAddress, DWORD RVA, PDWORD pFOA);

private:
    Ui::MainWindow *ui;
#ifdef DEBUG
    QPushButton *btnTest;
#endif
    bool showDetail;
    int curLine;
    QString *pOutputResult;
    QString fileName;
    FileBuffer fileBuffer;
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNTHeader;
    PIMAGE_FILE_HEADER pPEHeader;
    PIMAGE_OPTIONAL_HEADER32 pOptionHeader;
    PIMAGE_SECTION_HEADER pSectionHeader;
};

#endif // MAINWINDOW_H
