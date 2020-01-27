TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpthread -lglog -lnetfilter_queue

SOURCES += \
    Src/IpChanger.cpp \
    Src/IpFlowManager.cpp \
    Src/LogManager.cpp \
    Src/NetfilterManager.cpp \
    Src/main.cpp \
    Src/pol4b_ip.cpp \
    Src/pol4b_mac.cpp \
    Src/pol4b_tcp.cpp \
    Src/pol4b_transport.cpp \
    Src/pol4b_udp.cpp \
    Src/pol4b_util.cpp

HEADERS += \
    Src/FlowManager.h \
    Src/FlowManager.hpp \
    Src/IpChanger.h \
    Src/IpFlowManager.h \
    Src/LogManager.h \
    Src/NetfilterManager.h \
    Src/pol4b_ip.h \
    Src/pol4b_mac.h \
    Src/pol4b_tcp.h \
    Src/pol4b_transport.h \
    Src/pol4b_udp.h \
    Src/pol4b_util.h
