#pragma once

#include <string>
#include <vector>
#include <functional>
#include <atomic>

struct ScanResult {
    std::string ip;
    int port;
    bool open;
    std::string banner;
};

struct ScanConfig {
    std::string ip_start;
    std::string ip_end;
    int port_start;
    int port_end;
    int threads;
    int timeout_ms;
    bool grab_banner;
};

using ResultCallback = std::function<void(const ScanResult&)>;

class PortScanner {
public:
    explicit PortScanner(const ScanConfig& config);

    void scan(const ResultCallback& on_result);
    void stop();

private:
    ScanConfig config_;
    std::atomic<bool> stopped_{false};

    bool scan_port(const std::string& ip, int port, ScanResult& result);
    std::vector<std::string> expand_ip_range(const std::string& start, const std::string& end);
    static uint32_t ip_to_int(const std::string& ip);
    static std::string int_to_ip(uint32_t n);
    std::string grab_banner(int sock_fd);
};
