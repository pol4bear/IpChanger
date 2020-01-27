#include "LogManager.h"

using namespace std;
using namespace google;

namespace pol4b {
LogManager::LogManager(char *log_entry) {
    InitGoogleLogging(log_entry);
    LogToStderr();
}

LogManager::LogManager(string log_entry) {
    LogManager(log_entry.c_str());
}

void LogManager::on_info(string message) {
    LOG(INFO) << message;
}

void LogManager::on_warnig(string message) {
    LOG(WARNING) << message;
}

void LogManager::on_error(int code) {
    switch(code) {
    case NetfilterManager::Error::ALREADY_STARTED:
        LOG(ERROR) << "TcpDataChanger already started";
        break;
    case NetfilterManager::Error::NFQ_OPEN:
        LOG(ERROR) << "Cannot open NFQ";
        exit(NetfilterManager::Error::NFQ_OPEN);
        break;
    case NetfilterManager::Error::NFQ_UNBIND:
        LOG(ERROR) << "Cannot unbind NFQ";
        exit(NetfilterManager::Error::NFQ_UNBIND);
        break;
    case NetfilterManager::Error::NFQ_BIND:
        LOG(ERROR) << "Cannot bind NFQ";
        exit(NetfilterManager::Error::NFQ_BIND);
        break;
    case NetfilterManager::Error::NFQ_CREATE_QUEUE:
        LOG(ERROR) << "Cannot create NFQ queue";
        exit(NetfilterManager::Error::NFQ_CREATE_QUEUE);
        break;
    case NetfilterManager::Error::NFQ_SET_MODE:
        LOG(ERROR) << "Cannot set NFQ mode";
        exit(NetfilterManager::Error::NFQ_SET_MODE);
        break;
    case NetfilterManager::Error::PTHREAD_CREATE:
        LOG(ERROR) << "Cannot create pthread";
        exit(NetfilterManager::Error::PTHREAD_CREATE);
        break;
    case NetfilterManager::Error::PTHREAD_DETACH:
        LOG(ERROR) << "Cannot detatch pthread";
        exit(NetfilterManager::Error::PTHREAD_DETACH);
        break;
    case NetfilterManager::Error::NFQ_LOSING_PACKETS:
        LOG(ERROR) << "Losing Packets";
        break;
    case NetfilterManager::Error::NFQ_RECV:
        LOG(ERROR) << "Cannot receive packet from NFQ";
        break;
    case NetfilterManager::Error::NFQ_GET_PACKET_HEADER:
        LOG(ERROR) << "Cannot get packet header";
        break;
    case NetfilterManager::Error::NFQ_GET_PAYLOAD:
        LOG(ERROR) << "Cannot get payload";
        break;
    }
}
}

