# CMake最低版本要求
cmake_minimum_required(VERSION 3.10)

# 项目名称
project(IPv6Receiver)

# 设置C++标准
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# 设置可执行文件的输出目录为 ../bin
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ../bin)

# 查找PCAP库
find_library(PCAP_LIBRARY pcap)
if(NOT PCAP_LIBRARY)
    message(FATAL_ERROR "libpcap not found")
endif()

# 包含目录（这里指定的是系统包含PCAP的目录，可能不同平台路径不同）
include_directories(/usr/include)

# 查找当前目录中的所有源文件
file(GLOB SOURCES "*.cpp")

# 打印找到的源文件，用于调试
message(STATUS "Found source files: ${SOURCES}")

# 生成可执行文件，名为 ipv6_receiver
add_executable(ipv6_receiver ${SOURCES})

# 链接PCAP库
target_link_libraries(ipv6_receiver ${PCAP_LIBRARY})

