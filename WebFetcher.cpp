#include "WebFetcher.h"

// 构造函数
WebFetcher::WebFetcher() {
    curl_global_init(CURL_GLOBAL_DEFAULT); // 初始化libcurl
}

// 析构函数
WebFetcher::~WebFetcher() {
    curl_global_cleanup(); // 清理libcurl
}

// 获取网页数据
std::string WebFetcher::fetchData(const std::string& url) {
    CURL* curl = curl_easy_init(); // 初始化CURL句柄
    std::string readBuffer; // 存储网页数据

    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str()); // 设置URL
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback); // 设置写入回调函数
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer); // 设置写入数据的目标

        // 执行请求
        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
        }

        curl_easy_cleanup(curl); // 清理CURL句柄
    }

    return readBuffer; // 返回获取的网页数据
}

// 数据写入回调函数
size_t WebFetcher::WriteCallback(void* contents, size_t size, size_t nmemb, std::string* userp) {
    size_t totalSize = size * nmemb; // 计算数据总大小
    userp->append((char*)contents, totalSize); // 将数据追加到目标字符串
    return totalSize; // 返回写入的字节数
}
