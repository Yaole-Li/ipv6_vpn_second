 #include "ipv6_receiver.h"
#include <iostream>

int main() {
    // 目标IPv6地址
    std::string targetIPv6Address = "2a02:4780:12:e732::1";

    // 启动捕获程序
    captureIPv6Packets(targetIPv6Address);

    return 0;
}

