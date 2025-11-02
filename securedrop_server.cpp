/*
 * SecureDrop Server Application
 * Author: Michael Semera
 * 
 * Usage: ./securedrop_server <port> <cert_file> <key_file>
 */

#include "securedrop.h"
#include <csignal>
#include <sys/stat.h>

SecureDropServer* global_server = nullptr;

void signal_handler(int signum) {
    std::cout << "\nShutting down server..." << std::endl;
    if (global_server) {
        global_server->stop();
    }
    exit(signum);
}

void create_directories() {
    // Create necessary directories
    mkdir("uploads", 0755);
    mkdir("files", 0755);
    mkdir("logs", 0755);
}

int main(int argc, char* argv[]) {
    // Register signal handler
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Parse command line arguments
    int port = DEFAULT_PORT;
    std::string cert_file = "server.crt";
    std::string key_file = "server.key";
    
    if (argc > 1) {
        port = std::atoi(argv[1]);
    }
    if (argc > 2) {
        cert_file = argv[2];
    }
    if (argc > 3) {
        key_file = argv[3];
    }
    
    std::cout << "============================================" << std::endl;
    std::cout << "   SecureDrop Server v1.0" << std::endl;
    std::cout << "   Author: Michael Semera" << std::endl;
    std::cout << "============================================" << std::endl;
    std::cout << std::endl;
    
    // Create necessary directories
    create_directories();
    
    try {
        SecureDropServer server(port, cert_file, key_file);
        global_server = &server;
        
        server.start();
        
    } catch (const SecureDropException& e) {
        std::cerr << "Server error: " << e.what() << std::endl;
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Unexpected error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}