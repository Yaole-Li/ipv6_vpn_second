#ifndef IPV6_RECEIVER_H
#define IPV6_RECEIVER_H

#include <pcap.h>
#include <netinet/ip6.h>
#include <netinet/if_ether.h>
#include <string>

// 定义IPv6目的选项扩展头的结构
struct IPv6DestinationOptionsHeader {
    uint8_t nextHeader;        // 下一个报头的类型
    uint8_t hdrExtLen;         // 扩展头长度
    char textData[255];        // 存储文本信息
};

// 捕获并处理数据包
void captureIPv6Packets(const std::string& filterAddress);

// 解析扩展头并输出文本信息
void parseAndPrintExtensionHeader(const u_char* packet);

// 解析并输出IPv6报头信息
void parseAndPrintIPv6Header(const u_char* packet);

#endif

