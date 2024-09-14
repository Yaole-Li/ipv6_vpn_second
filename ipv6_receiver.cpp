#include "ipv6_receiver.h"
#include <iostream>
#include <arpa/inet.h>
#include <cstring>

// 解析并输出IPv6报头信息
void parseAndPrintIPv6Header(const u_char* packet) {
    // 跳过以太网头部（通常14字节）到IPv6报头
    const struct ip6_hdr* ipv6Header = (struct ip6_hdr*)(packet + sizeof(struct ether_header));

    // 获取源地址和目标地址
    char srcAddrStr[INET6_ADDRSTRLEN], destAddrStr[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &(ipv6Header->ip6_src), srcAddrStr, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(ipv6Header->ip6_dst), destAddrStr, INET6_ADDRSTRLEN);

    std::cout << "[DEBUG] Source Address: " << srcAddrStr << std::endl;
    std::cout << "[DEBUG] Destination Address: " << destAddrStr << std::endl;

    // 检查是否为扩展头
    if (ipv6Header->ip6_nxt != 60) {
        std::cerr << "[WARNING] No Destination Options Header found, next header: " << (int)ipv6Header->ip6_nxt << std::endl;
    }
}

// 解析扩展头并输出文本信息
void parseAndPrintExtensionHeader(const u_char* packet) {
    const struct ip6_hdr* ipv6Header = (struct ip6_hdr*)(packet + sizeof(struct ether_header));

    if (ipv6Header->ip6_nxt == 60) {
        std::cout << "[DEBUG] Destination Options Header found!" << std::endl;

        // 偏移到扩展头部后的位置
        const u_char* extensionHeader = packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr);

        // 扩展头的前两个字段是 Next Header 和 Hdr Ext Len
        uint8_t nextHeader = extensionHeader[0];
        uint8_t hdrExtLen = extensionHeader[1];

        // 文本数据从第3个字节开始
        const char* textData = (const char*)(extensionHeader + 2);

        std::cout << "[DEBUG] Next Header: " << (int)nextHeader << std::endl;
        std::cout << "[DEBUG] Header Extension Length: " << (int)hdrExtLen << std::endl;
        std::cout << "[DEBUG] Text Data in Extension Header: " << textData << std::endl;

        if (strlen(textData) == 0) {
            std::cerr << "[WARNING] No text data found in the Destination Options Header." << std::endl;
        }
    } else {
        std::cerr << "[WARNING] Expected Destination Options Header but found another header: " << (int)ipv6Header->ip6_nxt << std::endl;
    }
}

// 数据包处理回调函数
void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    std::cout << "[INFO] Packet captured of length: " << pkthdr->len << " bytes" << std::endl;

    // 解析IPv6报头
    parseAndPrintIPv6Header(packet);

    // 解析并输出扩展头中的文本信息
    parseAndPrintExtensionHeader(packet);

    std::cout << "[INFO] Packet processing complete." << std::endl;
    std::cout << "----------------------------------------" << std::endl;
}

// 捕获IPv6数据包
void captureIPv6Packets(const std::string& filterAddress) {
    char errorBuffer[PCAP_ERRBUF_SIZE];
    pcap_if_t* devices;
    pcap_if_t* device;

    // 获取可用设备列表
    if (pcap_findalldevs(&devices, errorBuffer) == -1) {
        std::cerr << "[ERROR] Error finding devices: " << errorBuffer << std::endl;
        return;
    }

    // 打印设备列表并选择一个设备
    std::cout << "[INFO] Available devices:" << std::endl;
    int i = 0;
    for (device = devices; device != NULL; device = device->next) {
        std::cout << ++i << ". " << device->name;
        if (device->description) {
            std::cout << " - " << device->description << std::endl;
        } else {
            std::cout << " - No description available" << std::endl;
        }
    }

    // 使用第一个可用设备
    device = devices;
    std::cout << "[INFO] Using device: " << device->name << std::endl;

    // 打开设备进行监听
    pcap_t* handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errorBuffer);
    if (handle == NULL) {
        std::cerr << "[ERROR] Could not open device " << device->name << ": " << errorBuffer << std::endl;
        return;
    }

    // 设置过滤器
    struct bpf_program fp;
    std::string filter_exp = "ip6 and dst host " + filterAddress;
    if (pcap_compile(handle, &fp, filter_exp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "[ERROR] Could not parse filter " << filter_exp << ": " << pcap_geterr(handle) << std::endl;
        return;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "[ERROR] Could not install filter " << filter_exp << ": " << pcap_geterr(handle) << std::endl;
        return;
    }

    std::cout << "[INFO] Listening for IPv6 packets sent to " << filterAddress << "..." << std::endl;

    // 开始捕获数据包
    pcap_loop(handle, 0, packetHandler, NULL);

    pcap_close(handle);
    pcap_freealldevs(devices);
}

