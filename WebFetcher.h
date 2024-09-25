#ifndef WEBFETCHER_H
#define WEBFETCHER_H

#include <string>
#include <curl/curl.h>
#include <iostream>

class WebFetcher {
public:
    WebFetcher(); // 构造函数
    ~WebFetcher(); // 析构函数

    std::string fetchData(const std::string& url); // 获取网页数据

private:
    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* userp); // 数据写入回调函数
};

#endif // WEBFETCHER_H
