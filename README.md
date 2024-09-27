# IPv6 Packet Sender

## 项目简介

本项目包含三个主要部分：`IPv6Packet` 类、`WebFetcher` 类和一个示例程序 `main.cpp`。该项目的主要功能是从指定的 URL 获取网页数据，并将其分段通过 IPv6 数据包发送到指定的目标地址。

## 文件结构

- `IPv6Packet.h` 和 `IPv6Packet.cpp`：定义并实现了 `IPv6Packet` 类，用于构建和发送 IPv6 数据包。
- `WebFetcher.h` 和 `WebFetcher.cpp`：定义并实现了 `WebFetcher` 类，用于从指定的 URL 获取网页数据。
- `main.cpp`：示例程序，演示如何使用 `IPv6Packet` 和 `WebFetcher` 类。

## 代码功能

### IPv6Packet 类

- **构造函数**：初始化目标地址、扩展头字段和数据字段，创建 libpcap 句柄。
- **析构函数**：释放内存和关闭 libpcap 句柄。
- **`buildPacket` 函数**：构建完整的 IPv6 数据包。
- **`sendPackets` 函数**：发送指定次数的数据包。
- **`printPacketInfo` 函数**：输出数据包信息。
- **`getMacAddress` 函数**：获取本地 MAC 地址。
- **`getLocalIPv6Addr` 函数**：获取本地 IPv6 地址，忽略链路本地地址和回环地址。

### WebFetcher 类

- **构造函数**：初始化 libcurl。
- **析构函数**：清理 libcurl。
- **`fetchData` 函数**：从指定的 URL 获取网页数据。
- **`WriteCallback` 函数**：数据写入回调函数，将数据追加到目标字符串。

### main.cpp

- **功能**：示例程序，演示如何使用 `IPv6Packet` 和 `WebFetcher` 类。
  - 从指定的 URL 获取网页数据。
  - 将网页数据分段，每段最大 1280 字节。
  - 构建并发送 IPv6 数据包，每个数据包包含一个扩展头字段和一段网页数据。
  - 输出每个数据包的信息。