#include <iostream>
#include "IpChanger.h"
#include "LogManager.h"

using namespace std;
using namespace pol4b;

int main(int argc, char *argv[]) {
    LogManager log_manager(argv[0]);
    int input_queue = 0;
    int output_queue = 1;
    Ip destination_ip;
    uint16_t destination_port;
    switch(argc) {
    case 5: input_queue = atoi(argv[3]); output_queue = atoi(argv[4]);
    case 3: destination_ip = Ip(argv[1]); destination_port = atoi(argv[2]); break;
    default: LOG(ERROR) << "Usage: " << argv[0] << "[Destination IP] [Destination Port] [Input Queue Number] [Output Queue Number]"; exit(0);
    }
    IpChanger ip_changer(LogManager::on_error, LogManager::on_info);
    ip_changer.start(input_queue, output_queue, destination_ip, destination_port);
    LogManager::on_info("IpChanger Started");
    while (ip_changer.is_started());
    LogManager::on_info("IpChanger Exited");
}
