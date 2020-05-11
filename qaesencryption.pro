QT += core testlib
QT -= gui

CONFIG += c++11

TARGET = QAESEncryption
CONFIG += console
CONFIG -= app_bundle

TEMPLATE = app

yasm.name = yasm ${QMAKE_FILE_IN}.s
yasm.input = ASM_FILES
yasm.variable_out = OBJECTS
yasm.commands = yasm D__linux__ -g dwarf2 -f elf64 ${QMAKE_FILE_IN} -o ${QMAKE_FILE_OUT}
yasm.output = ${QMAKE_FILE_IN_PATH}${QMAKE_FILE_IN_BASE}$${first(QMAKE_EXT_OBJ)}
yasm.CONFIG += target_predeps

ASM_FILES += intel_aes_lib/asm/x64/do_rdtsc.s
ASM_FILES += intel_aes_lib/asm/x64/iaesx64.s

QMAKE_EXTRA_COMPILERS  += yasm


# The following define makes your compiler emit warnings if you use
# any feature of Qt which as been marked deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

DEFINES += USE_INTEL_AES_IF_AVAILABLE
QMAKE_CXXFLAGS += -maes

INCLUDEPATH += intel_aes_lib/include/

# You can also make your code fail to compile if you use deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

HEADERS += \
    qaesencryption.h \
    unit_test/aestest.h \

SOURCES += main.cpp \
    qaesencryption.cpp \
    unit_test/aestest.cpp \
    aesni-util.c

DISTFILES += \
    unit_test/longText.txt

RESOURCES += \
    res.qrc

