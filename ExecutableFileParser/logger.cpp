#include <stdarg.h>
#include <time.h>
#include "logger.h"
#include <QDateTime>

unsigned int log_level = LEVEL_DEBUG;
static FILE *log_file = NULL;

unsigned long get_file_size(const char *path)  
{  
    unsigned long filesize = -1;
    FILE *fp;
    fp = ::fopen(path, "r");
    if(fp == NULL)
        return filesize;
    fseek(fp, 0L, SEEK_END);
    filesize = ftell(fp);
    fclose(fp);
    return filesize;
}  

void log_init(const char *log_file_name)
{
    unsigned long filesize = get_file_size(log_file_name);
    if (filesize > MAX_LOG_FILE_SIZE){
#ifdef WIN32
        DeleteFileA(log_file_name);
#else
        remove(log_file_name);
#endif
    }
    log_file = ::fopen(log_file_name, "a");

    if (log_file == NULL) {
        fprintf(stderr, "Failed to open log file %s\n", log_file_name);
        return;
    }
}

void log_cleanup(void)
{
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
}

void log_write(unsigned int type,const char *file, const char *function, const int line, const char *format, ...)
{
    va_list para;
    const char *type_as_char[] = { "DEBUG", "INFO", "ERROR" };

    if (type < LEVEL_DEBUG || type > LEVEL_ERROR){
        fprintf(stderr, "Invalid parameter [type]\n");
        return;
    }

    if (type < log_level) {
        return;
    }

    QDateTime sysDateTime;
    QString qtime = sysDateTime.currentDateTime().toString("yyyyMMdd hh:mm:ss");
    va_start(para, format);
    fprintf(log_file,"%s %s %s:%s:%d [pid:%d,tid:%d]:", qtime.toStdString().c_str(), type_as_char[type], file, function, line, PID, TID);
    vfprintf (log_file, format, para);
    va_end(para);
    fprintf (log_file, "\n");
    fflush(log_file);
    return;
}
