#pragma once

#include "FlowManager.h"

namespace pol4b {
template<typename T1, typename T2>
FlowManager<T1, T2>::FlowManager() : remove_period(DEFAULT_PERIOD) {
    timeouts.reserve(State::GENERIC + 1);
    for (int i = State::TCP_SYN; i <= State::GENERIC; i++) timeouts[i] = Timeouts::get_default_timeout(i);
}

template<typename T1, typename T2>
void *FlowManager<T1, T2>::remove_loop(void *input) {
    FlowManager<T1, T2> *handle = (FlowManager<T1, T2>*)input;

    while(handle->remove_period > 0) {
        sleep(handle->remove_period);
        handle->mutex.lock();
        auto now = std::chrono::system_clock::now();
        for (auto it = handle->flow_map.begin(); it != handle->flow_map.end(); it++) {
            auto diff = now - it->second.last_communication;

            if (diff >= handle->timeouts[it->second.state])
                handle->flow_map.erase(it->first);
        }
        handle->mutex.unlock();
    }
}

template<typename T1, typename T2>
int FlowManager<T1, T2>::get_period() {
    return remove_period;
}

template<typename T1, typename T2>
int FlowManager<T1, T2>::get_timeout(int state) {
    if(state < State::TCP_SYN || state > State::GENERIC) return 0;

    return timeouts[state];
}

template<typename T1, typename T2>
void FlowManager<T1, T2>::set_period(int period) {
    if (period < 0) return;

    pthread_cancel(remove_job);
    remove_period = period;
    if (period == 0) return;
    pthread_create(&remove_job, nullptr, remove_loop, this);
    return;
}

template<typename T1, typename T2>
void FlowManager<T1, T2>::set_timeout(int state, int seconds) {
    if(state < State::TCP_SYN || state > State::GENERIC) return;
    else if(seconds < 0) return;

    timeouts[state] = seconds;
}

template<typename T1, typename T2>
FlowManager<T1, T2>::FlowValue::FlowValue() {}

template<typename T1, typename T2>
int FlowManager<T1, T2>::Timeouts::get_default_timeout(int state) {
    switch(state) {
    case State::TCP_SYN: return DEF_TCP_SYN;
    case State::TCP_SYN_RECEIVED: return DEF_TCP_SYN_RECEIVED;
    case State::TCP_ESTABLISHED: return DEF_TCP_ESTABLISHED;
    case State::TCP_FIN_WAIT: return DEF_TCP_FIN_WAIT;
    case State::TCP_CLOSE_WAIT: return DEF_TCP_CLOSE_WAIT;
    case State::TCP_LAST_ACK: return DEF_TCP_LAST_ACK;
    case State::TCP_TIME_WAIT: return DEF_TCP_TIME_WAIT;
    case State::TCP_CLOSE: return DEF_TCP_CLOSE;
    case State::UDP: return DEF_UDP;
    case State::UDP_STREAM: return DEF_UDP_STREAM;
    case State::ICMP: return DEF_ICMP;
    case State::GENERIC: return DEF_GENERIC;
    default: return -1;
    }
}

}
