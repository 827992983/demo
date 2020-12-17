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

private:
    void appendTextEdit(QString data);

private:
    Ui::MainWindow *ui;
#ifdef DEBUG
    QPushButton *btnTest;
#endif
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
