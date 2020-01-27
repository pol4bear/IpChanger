#pragma once

#include <chrono>
#include <map>
#include <mutex>
#include <unistd.h>
#include <vector>

namespace pol4b {
template<typename T1, typename T2>
class FlowManager {
public:
    class FlowValue;
    using FlowMap = std::map<T1,FlowValue>;

    FlowManager();

protected:
    static const int DEFAULT_PERIOD = 60;
    static void *remove_loop(void *input);

public:
    int get_period();
    int get_timeout(int state);
    void set_period(int period);
    void set_timeout(int state, int seconds);

    virtual void assign_input(uint8_t *packet) = 0;
    virtual void assign_output(uint8_t *packet) = 0;

protected:
    int remove_period;
    pthread_t remove_job;
    std::mutex mutex;
    std::vector<int> timeouts;
    FlowMap flow_map;

public:
    class FlowValue {
    public:
        FlowValue();

        std::chrono::time_point<std::chrono::system_clock> last_communication;
        int state;
        T2 value;
    };

    class State {
    public:
        enum {
            TCP_SYN = 0,
            TCP_SYN_RECEIVED,
            TCP_ESTABLISHED,
            TCP_FIN_WAIT,
            TCP_CLOSE_WAIT,
            TCP_LAST_ACK,
            TCP_TIME_WAIT,
            TCP_CLOSE,
            UDP,
            UDP_STREAM,
            ICMP,
            GENERIC
        };
    };

    class Timeouts {
    public:
        static const int DEF_TCP_SYN = 20;
        static const int DEF_TCP_SYN_RECEIVED = 60;
        static const int DEF_TCP_ESTABLISHED = 86400;
        static const int DEF_TCP_FIN_WAIT = 120;
        static const int DEF_TCP_CLOSE_WAIT = 60;
        static const int DEF_TCP_LAST_ACK = 30;
        static const int DEF_TCP_TIME_WAIT = 10;
        static const int DEF_TCP_CLOSE = 10;
        static const int DEF_UDP = 30;
        static const int DEF_UDP_STREAM = 180;
        static const int DEF_ICMP = 30;
        static const int DEF_GENERIC = 600;

        static int get_default_timeout(int state);
    };
};
}

#include "FlowManager.hpp"
