# 设置 PKG_CONFIG_EXECUTABLE 的路径
set(PKG_CONFIG_EXECUTABLE /opt/homebrew/bin/pkg-config)

# 设置 PKG_CONFIG_PATH
set(ENV{PKG_CONFIG_PATH} "/opt/homebrew/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")

# 明确指定 libpcap 的位置
set(PCAP_ROOT_DIR "/opt/homebrew/opt/libpcap")

cmake_minimum_required(VERSION 3.10)

# 项目名称
project(IPv6PacketSender)

# 设置 C++ 标准
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# 设置 libpcap 的路径
set(PCAP_ROOT_DIR "/opt/homebrew/opt/libpcap")
set(PCAP_INCLUDE_DIR "${PCAP_ROOT_DIR}/include")
set(PCAP_LIBRARY "${PCAP_ROOT_DIR}/lib/libpcap.dylib")

# 设置 pkg-config 路径
set(ENV{PKG_CONFIG_PATH} "${PCAP_ROOT_DIR}/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")

# 设置编译器标志
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -I${PCAP_INCLUDE_DIR}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -I${PCAP_INCLUDE_DIR}")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -L${PCAP_ROOT_DIR}/lib")

# 查找 libcurl 库
find_package(CURL REQUIRED)

# 包含头文件目录
include_directories(${PCAP_INCLUDE_DIR} ${CURL_INCLUDE_DIRS})

# 源文件列表
set(SOURCES
    main.cpp
    IPv6Packet.cpp
    WebFetcher.cpp
)

# 生成可执行文件
add_executable(visit_demo ${SOURCES})

# 链接库
target_link_libraries(visit_demo ${PCAP_LIBRARY} ${CURL_LIBRARIES})

# 设置可执行文件输出目录
set_target_properties(visit_demo PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ../bin
)

# 打印调试信息
message(STATUS "PCAP_INCLUDE_DIR: ${PCAP_INCLUDE_DIR}")
message(STATUS "PCAP_LIBRARY: ${PCAP_LIBRARY}")
