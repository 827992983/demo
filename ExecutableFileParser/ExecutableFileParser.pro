#-------------------------------------------------
#
# Project created by QtCreator 2020-12-16T11:15:09
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = ExecutableFileParser
TEMPLATE = app


SOURCES += main.cpp\
        mainwindow.cpp \
        logger.cpp \
        pe_parser.cpp

HEADERS  += mainwindow.h \
        logger.h \
        global_def.h \
        pe_parser.h

FORMS    += mainwindow.ui

DISTFILES += \
    ReadMe.md
