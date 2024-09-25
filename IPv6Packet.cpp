#include "IPv6Packet.h"
#include <net/ethernet.h>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <unistd.h> // for close()

// 构造函数，初始化目标地址、扩展头字段和数据字段，创建 libpcap 句柄
IPv6Packet::IPv6Packet(const std::string& dst_addr, const std::string& ext_field, const std::string& data_field)
    : dst_addr_(dst_addr), ext_field_(ext_field), data_field_(data_field), packet_len_(0) {

    // 打开网络设备以进行发送
    char errbuf[PCAP_ERRBUF_SIZE];
    handle_ = pcap_open_live("en0", BUFSIZ, 1, 1000, errbuf); // 替换为实际的网络接口名称
    if (handle_ == nullptr) {
        std::cerr << "无法打开设备: " << errbuf << std::endl;
        return;
    }

    // 获取本机 MAC 地址
    local_mac_ = getMacAddress();

    // 预留空间：以太网头部 + IPv6 头部 + 扩展头 + 扩展头字段 + 数据字段
    // packet_ = new char[sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(uint8_t) + sizeof(uint8_t) + data_field_.length() + 24];
    // packet_ = new char[sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(uint8_t) + sizeof(uint8_t) + ext_field_.length() + data_field_.length()];
    std::cout << "----------------------------------------------" << std::endl;
    packet_ = new char[1500];
    // std::cout << "预留空间大小为：" << sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(uint8_t) + sizeof(uint8_t) + ext_field_.length() + data_field_.length() << std::endl;
}

// 析构函数，释放内存和关闭 libpcap 句柄
IPv6Packet::~IPv6Packet() {
    delete[] packet_;
    pcap_close(handle_);
}

// 获取本地 MAC 地址的函数实现
std::string IPv6Packet::getMacAddress() const {
    std::string command = "ifconfig " + std::string("en0") + " | grep ether | awk '{print $2}'";
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        return "";
    }
    char buffer[128];
    std::string mac_address = "";
    while (!feof(pipe)) {
        if (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
            mac_address = buffer;
        }
    }
    pclose(pipe);
    mac_address.erase(mac_address.find_last_not_of(" \n\r\t")+1); // 移除可能存在的换行符
    return mac_address;
}

// 获取本地 IPv6 地址的函数实现，忽略链路本地地址和回环地址
std::string IPv6Packet::getLocalIPv6Addr() const {
    struct ifaddrs* ifAddrStruct = nullptr;
    struct ifaddrs* ifa = nullptr;
    void* tmpAddrPtr = nullptr;
    char addressBuffer[INET6_ADDRSTRLEN];

    getifaddrs(&ifAddrStruct);

    for (ifa = ifa != nullptr ? ifa : ifAddrStruct; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET6) {
            tmpAddrPtr = &((struct sockaddr_in6*)ifa->ifa_addr)->sin6_addr;
            inet_ntop(AF_INET6, tmpAddrPtr, addressBuffer, INET6_ADDRSTRLEN);

            // 忽略链路本地地址和环回地址
            std::string ipv6Address(addressBuffer);
            if (ipv6Address.find("fe80") == 0 || ipv6Address == "::1") {
                continue;
            }

            freeifaddrs(ifAddrStruct);
            return ipv6Address;
        }
    }

    freeifaddrs(ifAddrStruct);
    return "未找到 IPv6 地址";
}

// 构建完整的 IPv6 数据包
void IPv6Packet::buildPacket() {
    //packet_是一个指针
    struct ether_header* eth_hdr = reinterpret_cast<struct ether_header*>(packet_);
    struct ip6_hdr* ipv6_hdr = reinterpret_cast<struct ip6_hdr*>(packet_ + sizeof(struct ether_header));

    // 设置以太网头部字段
    uint8_t dest_mac[6];
    convertMacStringToBytes("bc:24:11:34:a8:90", dest_mac); // 目标 MAC 地址
    memcpy(eth_hdr->ether_dhost, dest_mac, ETH_ALEN); // 设置目标 MAC 地址
    memcpy(eth_hdr->ether_shost, local_mac_.c_str(), ETH_ALEN); // 设置源 MAC 地址为本机 MAC 地址
    eth_hdr->ether_type = htons(ETHERTYPE_IPV6);

    // 设置 IPv6 基础头部字段
    ipv6_hdr->ip6_flow = htonl((6 << 28) | 0); // 设置版本为 IPv6，流量控制为 0
    // ipv6_hdr->ip6_plen = htons(sizeof(uint8_t) + sizeof(uint8_t) + data_field_.length() + 24); // 有效载荷长度
    ipv6_hdr->ip6_plen = htons(2 + ext_field_.length() + data_field_.length()); // 有效载荷长度
    ipv6_hdr->ip6_nxt = 60; // 下一个头部类型为目的选项头部（60）
    ipv6_hdr->ip6_hops = 255;

    // 设置源地址和目标地址
    inet_pton(AF_INET6, getLocalIPv6Addr().c_str(), &ipv6_hdr->ip6_src);
    inet_pton(AF_INET6, dst_addr_.c_str(), &ipv6_hdr->ip6_dst);

    // 构建扩展头部字段
    uint8_t* ext_hdr = reinterpret_cast<uint8_t*>(packet_ + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
    
    ext_hdr[0] = 0x3B; // 下一个头部类型为无下一个头部
    ext_hdr[1] = (ext_field_.length() + 7) / 8; // 设置扩展头长度
    std::cout << "扩展头长度为：" << ext_field_.length() << std::endl;
    // ext_hdr[2] = std::stoi(ext_field_); // 添加序号，从扩展字段中提取，这句话应该不需要，因为ext_field中的第一个就是序号
    memcpy(ext_hdr + 2, ext_field_.c_str(), ext_field_.length()); // 存储扩展字段

    // 将用户输入的数据复制到有效负载部分
    char* payload = reinterpret_cast<char*>(ext_hdr + 2 + ((ext_field_.length() + 7) / 8)*8); // 指向扩展头之后的位置
    std::cout << "数据字段长度：" << data_field_.length() << std::endl;
    memcpy(payload, data_field_.c_str(), data_field_.length()); // 将用户输入的数据复制到负载中

    // 添加固定负载"TESTTESTTESTTESTTESTTEST"到负载部分
    // memcpy(payload + data_field_.length(), "TESTTESTTESTTESTTESTTEST", 24);

    // 更新数据包总长度：以太网头部 + IPv6 头部 + 扩展头 + 扩展头负载长度 + 有效负载长度
    // packet_len_ = sizeof(struct ether_header) + sizeof(struct ip6_hdr) + 2 + data_field_.length() + 24; 
    packet_len_ = sizeof(struct ether_header) + sizeof(struct ip6_hdr) + 2 + ext_field_.length() + data_field_.length();
}

// 发送数据包的函数实现，发送指定次数的数据包
void IPv6Packet::sendPackets(int count) {
    /*    for (int i = 0; i < count; ++i) {
        // 使用 pcap_sendpacket 函数发送数据包
        if (pcap_sendpacket(handle_, reinterpret_cast<const u_char*>(packet_), packet_len_) != 0) {
            std::cerr << "发送数据包 " << (i + 1) << " 失败: " << pcap_geterr(handle_) << std::endl;
        } else {
            std::cout << "数据包 " << (i + 1) << " 发送成功。" << std::endl;
        }
    }
    */
    // 使用 pcap_sendpacket 函数发送数据包，只发送一次
    if (pcap_sendpacket(handle_, reinterpret_cast<const u_char*>(packet_), packet_len_) != 0) {
        std::cerr << "发送数据包 " << (count) << " 失败: " << pcap_geterr(handle_) << std::endl;
    } else {
        std::cout << "数据包 " << (count) << " 发送成功。" << std::endl;
    }
}

// 输出数据包信息的函数实现
void IPv6Packet::printPacketInfo() const {
    std::cout << "源 MAC 地址: " << local_mac_ << std::endl;
    std::cout << "目标 MAC 地址: bc:24:11:34:a8:90" << std::endl;
    std::cout << "源 IPv6 地址: " << getLocalIPv6Addr() << std::endl;
    std::cout << "目标 IPv6 地址: " << dst_addr_ << std::endl;
    std::cout << "扩展头字段: " << ext_field_ << std::endl;
    std::cout << "用户数据: " << data_field_ << std::endl;
    std::cout << "总数据包长度: " << packet_len_ << " 字节" << std::endl;
}

// 将 MAC 地址字符串转换为字节数组
void convertMacStringToBytes(const std::string& mac_str, uint8_t* mac_bytes) {
    std::stringstream ss(mac_str);
    std::string item;
    int byteIndex = 0;
    while (std::getline(ss, item, ':') && byteIndex < ETH_ALEN) {
        mac_bytes[byteIndex++] = static_cast<uint8_t>(std::stoi(item, nullptr, 16));
    }
}
