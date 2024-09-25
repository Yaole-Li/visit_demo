#include "IPv6Packet.h"
#include "WebFetcher.h" // 确保包含获取网页数据的头文件
#include <string>

int main() {
    std::string url = "http://www.baidu.com"; // 访问的网页链接
    WebFetcher fetcher; // 创建 WebFetcher 实例
    std::string webData = fetcher.fetchData(url); // 获取网页数据

    // 分段发送数据包
    size_t offset = 0;
    int packetIndex = 0;

    while (offset < webData.length()) {
        // 计算当前段的数据长度，最大1280字节
        size_t chunkSize = std::min(size_t(1280), webData.length() - offset);
        std::string chunkData = webData.substr(offset, chunkSize); // 获取当前段数据

        // 创建扩展头内容：包序号 + URL
        std::string extField = std::to_string(packetIndex) + " " + url;

        // 创建 IPv6 数据包
        IPv6Packet packet("2a02:4780:12:e732::1", extField, chunkData); // 修改为合适的目标 IPv6 地址
        packet.buildPacket(); // 构建数据包

        // 发送数据包
        packet.sendPackets(packetIndex); // 发送一次数据包
        packet.printPacketInfo();

        offset += chunkSize; // 移动到下一个数据段
        packetIndex++; // 增加包序号
    }

    return 0; // 程序结束
}

//g++ -o visit_demo main.cpp IPv6Packet.cpp WebFetcher.cpp -lpcap -lcurl
