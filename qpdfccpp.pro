#-------------------------------------------------
#
# Project created by QtCreator 2013-05-19T14:30:20
#
#-------------------------------------------------

QT       += core gui widgets
CONFIG   += c++11

TARGET = qpdfccpp
TEMPLATE = app


SOURCES += main.cpp\
        qpdfccpp.cpp \
    qpdfccpp-0.2/pdfinfo.cpp \
    qpdfccpp-0.2/pdfcrack.cpp \
    qpdfccpp-0.2/md5.cpp \
    qpdfccpp-0.2/rc4.cpp \
    qpdfccpp-0.2/pdfworkspace.cpp

HEADERS  += qpdfccpp.h \
    qpdfccpp-0.2/pdfinfo.hpp \
    qpdfccpp-0.2/common.hpp \
    qpdfccpp-0.2/pdfcrack.hpp \
    qpdfccpp-0.2/md5.hpp \
    qpdfccpp-0.2/rc4.hpp \
    qpdfccpp-0.2/pdfworkspace.hpp

FORMS    += qpdfccpp.ui
