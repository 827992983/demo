#include "mainwindow.h"
#include <QApplication>
#include "logger.h"
#include "global_def.h"

int main(int argc, char *argv[])
{
    int ret = 0;

    log_init(LOG_FILE_PATH);
    LOG_INFO("*** ExecutableFileParser Start ***");

    QApplication a(argc, argv);
    MainWindow w;
    w.show();
    ret = a.exec();

    LOG_INFO("*** ExecutableFileParser Exit ***");
    log_cleanup();
    return ret;
}
