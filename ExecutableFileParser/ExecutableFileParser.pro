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
        file_parser.cpp

HEADERS  += mainwindow.h \
        global_def.h \
        elf.h \
        file_parser.h

FORMS    += mainwindow.ui

DISTFILES += \
    ReadMe.md
