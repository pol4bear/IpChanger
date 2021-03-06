#pragma once

#include <glog/logging.h>
#include "NetfilterManager.h"

namespace pol4b {
class LogManager
{
public:
    LogManager(char *log_entry);
    LogManager(std::string log_entry);

    static void on_info(std::string message);
    static void on_warnig(std::string message);
    static void on_error(int code);
};
}
