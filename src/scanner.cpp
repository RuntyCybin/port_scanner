#include "scanner.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/select.h>

#include <stdexcept>
#include <sstream>
#include <thread>
#include <mutex>
#include <queue>
#include <condition_variable>
#include <cstring>

PortScanner::PortScanner(const ScanConfig& config) : config_(config) {}

void PortScanner::stop() {
    stopped_ = true;
}

uint32_t PortScanner::ip_to_int(const std::string& ip) {
    struct in_addr addr{};
    if (inet_pton(AF_INET, ip.c_str(), &addr) != 1)
        throw std::invalid_argument("Invalid IP: " + ip);
    return ntohl(addr.s_addr);
}

std::string PortScanner::int_to_ip(uint32_t n) {
    struct in_addr addr{};
    addr.s_addr = htonl(n);
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    return {buf};
}

std::vector<std::string> PortScanner::expand_ip_range(const std::string& start, const std::string& end) {
    uint32_t s = ip_to_int(start);
    uint32_t e = ip_to_int(end);
    if (s > e) throw std::invalid_argument("IP start must be <= IP end");
    std::vector<std::string> ips;
    ips.reserve(e - s + 1);
    for (uint32_t i = s; i <= e; ++i)
        ips.push_back(int_to_ip(i));
    return ips;
}

std::string PortScanner::grab_banner(int sock_fd) {
    char buf[256] = {};
    struct timeval tv{};
    tv.tv_sec = 0;
    tv.tv_usec = 500000; // 500ms
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(sock_fd, &fds);
    if (select(sock_fd + 1, &fds, nullptr, nullptr, &tv) > 0) {
        ssize_t n = recv(sock_fd, buf, sizeof(buf) - 1, 0);
        if (n > 0) {
            // Strip non-printable except newline/tab
            std::string banner;
            for (int i = 0; i < n; ++i) {
                char c = buf[i];
                if (c == '\n' || c == '\r') break;
                if (c >= 32 && c < 127) banner += c;
            }
            return banner;
        }
    }
    return {};
}

bool PortScanner::scan_port(const std::string& ip, int port, ScanResult& result) {
    result.ip   = ip;
    result.port = port;
    result.open = false;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;

    // Non-blocking
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(static_cast<uint16_t>(port));
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    connect(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));

    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(sock, &fds);

    struct timeval tv{};
    tv.tv_sec  = config_.timeout_ms / 1000;
    tv.tv_usec = (config_.timeout_ms % 1000) * 1000;

    if (select(sock + 1, nullptr, &fds, nullptr, &tv) > 0) {
        int err = 0;
        socklen_t len = sizeof(err);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len);
        if (err == 0) {
            result.open = true;
            if (config_.grab_banner)
                result.banner = grab_banner(sock);
        }
    }

    close(sock);
    return result.open;
}

void PortScanner::scan(const ResultCallback& on_result) {
    stopped_ = false;

    std::vector<std::string> ips = expand_ip_range(config_.ip_start, config_.ip_end);

    // Build work queue: {ip, port}
    using Task = std::pair<std::string, int>;
    std::queue<Task> queue;
    for (const auto& ip : ips)
        for (int p = config_.port_start; p <= config_.port_end; ++p)
            queue.push({ip, p});

    std::mutex queue_mutex;
    std::mutex result_mutex;

    auto worker = [&]() {
        while (!stopped_) {
            Task task;
            {
                std::lock_guard<std::mutex> lock(queue_mutex);
                if (queue.empty()) return;
                task = queue.front();
                queue.pop();
            }
            ScanResult result;
            scan_port(task.first, task.second, result);
            if (result.open) {
                std::lock_guard<std::mutex> lock(result_mutex);
                on_result(result);
            }
        }
    };

    int nthreads = std::min(config_.threads, static_cast<int>(queue.size()));
    std::vector<std::thread> workers;
    workers.reserve(nthreads);
    for (int i = 0; i < nthreads; ++i)
        workers.emplace_back(worker);
    for (auto& t : workers)
        t.join();
}
