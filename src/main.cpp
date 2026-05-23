#include "scanner.h"

#include <iostream>
#include <string>
#include <sstream>
#include <csignal>
#include <cstdlib>
#include <iomanip>
#include <mutex>

static PortScanner* g_scanner = nullptr;

void handle_signal(int) {
    if (g_scanner) g_scanner->stop();
    std::cout << "\n[!] Scan interrupted.\n";
}

static void print_usage(const char* prog) {
    std::cout
        << "Usage: " << prog << " [options]\n\n"
        << "Options:\n"
        << "  -s <IP>       Start IP (default: 127.0.0.1)\n"
        << "  -e <IP>       End IP   (default: same as start)\n"
        << "  -p <start-end>  Port range, e.g. 1-1024 (default: 1-1024)\n"
        << "  -t <n>        Threads  (default: 100)\n"
        << "  -T <ms>       Timeout in milliseconds (default: 1000)\n"
        << "  -b            Grab banners\n"
        << "  -h            Show this help\n\n"
        << "Examples:\n"
        << "  " << prog << " -s 192.168.1.1\n"
        << "  " << prog << " -s 192.168.1.1 -e 192.168.1.254 -p 20-443 -t 200 -b\n";
}

static bool parse_port_range(const std::string& arg, int& start, int& end) {
    auto pos = arg.find('-');
    if (pos == std::string::npos) {
        start = end = std::stoi(arg);
        return true;
    }
    start = std::stoi(arg.substr(0, pos));
    end   = std::stoi(arg.substr(pos + 1));
    return start >= 1 && end <= 65535 && start <= end;
}

int main(int argc, char* argv[]) {
    ScanConfig cfg;
    cfg.ip_start   = "127.0.0.1";
    cfg.ip_end     = "";
    cfg.port_start = 1;
    cfg.port_end   = 1024;
    cfg.threads    = 100;
    cfg.timeout_ms = 1000;
    cfg.grab_banner = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h") { print_usage(argv[0]); return 0; }
        else if (arg == "-s" && i + 1 < argc) cfg.ip_start = argv[++i];
        else if (arg == "-e" && i + 1 < argc) cfg.ip_end   = argv[++i];
        else if (arg == "-p" && i + 1 < argc) {
            if (!parse_port_range(argv[++i], cfg.port_start, cfg.port_end)) {
                std::cerr << "[-] Invalid port range.\n";
                return 1;
            }
        }
        else if (arg == "-t" && i + 1 < argc) cfg.threads    = std::stoi(argv[++i]);
        else if (arg == "-T" && i + 1 < argc) cfg.timeout_ms = std::stoi(argv[++i]);
        else if (arg == "-b") cfg.grab_banner = true;
        else { std::cerr << "[-] Unknown option: " << arg << "\n"; return 1; }
    }

    if (cfg.ip_end.empty()) cfg.ip_end = cfg.ip_start;

    std::cout << "[*] Scanning " << cfg.ip_start;
    if (cfg.ip_start != cfg.ip_end) std::cout << " - " << cfg.ip_end;
    std::cout << "  ports " << cfg.port_start << "-" << cfg.port_end
              << "  threads=" << cfg.threads
              << "  timeout=" << cfg.timeout_ms << "ms"
              << (cfg.grab_banner ? "  [banner]" : "") << "\n\n";

    std::signal(SIGINT, handle_signal);

    std::mutex print_mutex;
    std::atomic<int> open_count{0};

    PortScanner scanner(cfg);
    g_scanner = &scanner;

    scanner.scan([&](const ScanResult& r) {
        std::lock_guard<std::mutex> lock(print_mutex);
        ++open_count;
        std::cout << std::left
                  << std::setw(18) << r.ip
                  << "  port " << std::setw(6) << r.port
                  << "  OPEN";
        if (!r.banner.empty()) std::cout << "  [" << r.banner << "]";
        std::cout << "\n";
    });

    std::cout << "\n[*] Done. " << open_count.load() << " open port(s) found.\n";
    return 0;
}
