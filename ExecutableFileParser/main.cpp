#include "mainwindow.h"
#include <QApplication>
#include "global_def.h"

int main(int argc, char *argv[])
{
    int ret = 0;
    QApplication a(argc, argv);
    MainWindow w;
    w.show();
    ret = a.exec();
    return ret;
}
