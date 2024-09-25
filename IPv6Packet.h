#ifndef IPV6_PACKET_H
#define IPV6_PACKET_H

#include <iostream>
#include <string>
#include <pcap.h>
#include <netinet/ip6.h>
#include <ifaddrs.h>
#include <arpa/inet.h>

#define ETH_ALEN 6

class IPv6Packet {
public:
    // 构造函数：输入目标 IP 地址、扩展头字段和数据字段
    IPv6Packet(const std::string& dst_addr, const std::string& ext_field, const std::string& data_field);
    ~IPv6Packet(); // 析构函数

    void buildPacket(); // 构建完整的 IPv6 数据包
    void sendPackets(int count); // 发送数据包
    void printPacketInfo() const; // 打印数据包信息

private:
    std::string getMacAddress() const; // 获取本地 MAC 地址
    std::string getLocalIPv6Addr() const; // 获取本地 IPv6 地址

    pcap_t* handle_; // pcap 句柄
    char* packet_; // 存储数据包
    size_t packet_len_; // 数据包长度
    std::string dst_addr_; // 目标地址
    std::string ext_field_; // 扩展头字段
    std::string data_field_; // 数据字段
    std::string local_mac_; // 本地 MAC 地址
};

// 将 MAC 地址字符串转换为字节数组
void convertMacStringToBytes(const std::string& mac_str, uint8_t* mac_bytes);

#endif // IPV6_PACKET_H
