/*
 * SecureDrop: Secure File Transfer Protocol
 * Author: Michael Semera
 * Description: High-performance secure file transfer system with TLS encryption
 * 
 * This file contains the core implementation of the SecureDrop protocol
 */

#ifndef SECUREDROP_H
#define SECUREDROP_H

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstring>
#include <memory>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

// Protocol constants
constexpr int BUFFER_SIZE = 8192;
constexpr int MAX_FILENAME_LENGTH = 256;
constexpr int HASH_LENGTH = SHA256_DIGEST_LENGTH;
constexpr int DEFAULT_PORT = 8443;
constexpr int MAX_CONNECTIONS = 5;

// Protocol message types
enum class MessageType : uint8_t {
    AUTH_REQUEST = 0x01,
    AUTH_RESPONSE = 0x02,
    FILE_UPLOAD = 0x03,
    FILE_DOWNLOAD = 0x04,
    FILE_DATA = 0x05,
    FILE_COMPLETE = 0x06,
    ERROR_MSG = 0x07,
    HEARTBEAT = 0x08,
    DISCONNECT = 0x09
};

// Status codes
enum class StatusCode : uint8_t {
    SUCCESS = 0x00,
    AUTH_FAILED = 0x01,
    FILE_NOT_FOUND = 0x02,
    PERMISSION_DENIED = 0x03,
    TRANSFER_ERROR = 0x04,
    INVALID_REQUEST = 0x05
};

// Protocol header structure
struct ProtocolHeader {
    MessageType type;
    uint32_t payload_length;
    uint32_t sequence_number;
    uint8_t checksum[HASH_LENGTH];
} __attribute__((packed));

/*
 * SecureDropException - Custom exception class
 */
class SecureDropException : public std::exception {
private:
    std::string message;
public:
    explicit SecureDropException(const std::string& msg) : message(msg) {}
    const char* what() const noexcept override {
        return message.c_str();
    }
};

/*
 * PerformanceMetrics - Track transfer performance
 */
class PerformanceMetrics {
private:
    std::chrono::high_resolution_clock::time_point start_time;
    std::chrono::high_resolution_clock::time_point end_time;
    size_t bytes_transferred;
    
public:
    PerformanceMetrics() : bytes_transferred(0) {}
    
    void start() {
        start_time = std::chrono::high_resolution_clock::now();
    }
    
    void end() {
        end_time = std::chrono::high_resolution_clock::now();
    }
    
    void add_bytes(size_t bytes) {
        bytes_transferred += bytes;
    }
    
    double get_duration_ms() const {
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            end_time - start_time);
        return duration.count();
    }
    
    double get_throughput_mbps() const {
        double duration_sec = get_duration_ms() / 1000.0;
        if (duration_sec == 0) return 0;
        return (bytes_transferred * 8.0) / (duration_sec * 1000000.0);
    }
    
    size_t get_bytes_transferred() const {
        return bytes_transferred;
    }
};

/*
 * SecurityManager - Handle encryption and authentication
 */
class SecurityManager {
private:
    SSL_CTX* ctx;
    
    void initialize_openssl() {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
    }
    
    void cleanup_openssl() {
        EVP_cleanup();
    }
    
public:
    SecurityManager() : ctx(nullptr) {
        initialize_openssl();
    }
    
    ~SecurityManager() {
        if (ctx) {
            SSL_CTX_free(ctx);
        }
        cleanup_openssl();
    }
    
    SSL_CTX* create_server_context() {
        const SSL_METHOD* method = TLS_server_method();
        ctx = SSL_CTX_new(method);
        
        if (!ctx) {
            throw SecureDropException("Unable to create SSL context");
        }
        
        // Set security options
        SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | 
                           SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
        
        return ctx;
    }
    
    SSL_CTX* create_client_context() {
        const SSL_METHOD* method = TLS_client_method();
        ctx = SSL_CTX_new(method);
        
        if (!ctx) {
            throw SecureDropException("Unable to create SSL context");
        }
        
        return ctx;
    }
    
    void load_certificates(const std::string& cert_file, 
                          const std::string& key_file) {
        if (SSL_CTX_use_certificate_file(ctx, cert_file.c_str(), 
                                         SSL_FILETYPE_PEM) <= 0) {
            throw SecureDropException("Failed to load certificate");
        }
        
        if (SSL_CTX_use_PrivateKey_file(ctx, key_file.c_str(), 
                                       SSL_FILETYPE_PEM) <= 0) {
            throw SecureDropException("Failed to load private key");
        }
        
        if (!SSL_CTX_check_private_key(ctx)) {
            throw SecureDropException("Private key does not match certificate");
        }
    }
    
    static std::string compute_sha256(const std::vector<uint8_t>& data) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(data.data(), data.size(), hash);
        
        std::stringstream ss;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') 
               << static_cast<int>(hash[i]);
        }
        return ss.str();
    }
    
    static bool verify_checksum(const std::vector<uint8_t>& data, 
                               const uint8_t* expected_hash) {
        unsigned char computed_hash[SHA256_DIGEST_LENGTH];
        SHA256(data.data(), data.size(), computed_hash);
        return memcmp(computed_hash, expected_hash, SHA256_DIGEST_LENGTH) == 0;
    }
};

/*
 * SecureConnection - Wrapper for SSL connection
 */
class SecureConnection {
private:
    SSL* ssl;
    int socket_fd;
    uint32_t sequence_number;
    
public:
    SecureConnection(SSL* ssl_conn, int sock_fd) 
        : ssl(ssl_conn), socket_fd(sock_fd), sequence_number(0) {}
    
    ~SecureConnection() {
        if (ssl) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        if (socket_fd >= 0) {
            close(socket_fd);
        }
    }
    
    bool send_data(const void* data, size_t length) {
        int bytes_sent = SSL_write(ssl, data, length);
        return bytes_sent == static_cast<int>(length);
    }
    
    bool receive_data(void* buffer, size_t length) {
        int bytes_received = SSL_read(ssl, buffer, length);
        return bytes_received == static_cast<int>(length);
    }
    
    bool send_header(const ProtocolHeader& header) {
        return send_data(&header, sizeof(ProtocolHeader));
    }
    
    bool receive_header(ProtocolHeader& header) {
        return receive_data(&header, sizeof(ProtocolHeader));
    }
    
    uint32_t get_next_sequence() {
        return ++sequence_number;
    }
};

/*
 * SecureDropServer - Server implementation
 */
class SecureDropServer {
private:
    int server_socket;
    SecurityManager security_manager;
    SSL_CTX* ssl_context;
    int port;
    std::string cert_file;
    std::string key_file;
    bool running;
    
    int create_socket() {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            throw SecureDropException("Failed to create socket");
        }
        
        // Set socket options
        int opt = 1;
        if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
            close(sock);
            throw SecureDropException("Failed to set socket options");
        }
        
        return sock;
    }
    
    void bind_socket(int sock) {
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = INADDR_ANY;
        
        if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(sock);
            throw SecureDropException("Failed to bind socket");
        }
    }
    
    void handle_client(std::unique_ptr<SecureConnection> conn) {
        std::cout << "Client connected, handling requests..." << std::endl;
        
        try {
            while (running) {
                ProtocolHeader header;
                if (!conn->receive_header(header)) {
                    break;
                }
                
                switch (header.type) {
                    case MessageType::FILE_UPLOAD:
                        handle_file_upload(conn.get(), header);
                        break;
                    case MessageType::FILE_DOWNLOAD:
                        handle_file_download(conn.get(), header);
                        break;
                    case MessageType::DISCONNECT:
                        return;
                    default:
                        send_error(conn.get(), StatusCode::INVALID_REQUEST);
                        break;
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "Client handler error: " << e.what() << std::endl;
        }
    }
    
    void handle_file_upload(SecureConnection* conn, const ProtocolHeader& header) {
        // Receive filename
        std::vector<char> filename_buffer(MAX_FILENAME_LENGTH);
        if (!conn->receive_data(filename_buffer.data(), MAX_FILENAME_LENGTH)) {
            send_error(conn, StatusCode::TRANSFER_ERROR);
            return;
        }
        
        std::string filename(filename_buffer.data());
        filename = "uploads/" + filename;
        
        // Receive file size
        uint64_t file_size;
        if (!conn->receive_data(&file_size, sizeof(file_size))) {
            send_error(conn, StatusCode::TRANSFER_ERROR);
            return;
        }
        
        std::cout << "Receiving file: " << filename 
                  << " (" << file_size << " bytes)" << std::endl;
        
        PerformanceMetrics metrics;
        metrics.start();
        
        // Receive file data
        std::ofstream file(filename, std::ios::binary);
        if (!file.is_open()) {
            send_error(conn, StatusCode::PERMISSION_DENIED);
            return;
        }
        
        std::vector<uint8_t> buffer(BUFFER_SIZE);
        uint64_t received = 0;
        
        while (received < file_size) {
            size_t chunk_size = std::min(static_cast<uint64_t>(BUFFER_SIZE), 
                                        file_size - received);
            
            if (!conn->receive_data(buffer.data(), chunk_size)) {
                file.close();
                send_error(conn, StatusCode::TRANSFER_ERROR);
                return;
            }
            
            file.write(reinterpret_cast<char*>(buffer.data()), chunk_size);
            received += chunk_size;
            metrics.add_bytes(chunk_size);
        }
        
        file.close();
        metrics.end();
        
        // Send success response
        ProtocolHeader response;
        response.type = MessageType::FILE_COMPLETE;
        response.payload_length = 0;
        response.sequence_number = conn->get_next_sequence();
        conn->send_header(response);
        
        std::cout << "Upload complete: " << filename << std::endl;
        std::cout << "  Duration: " << metrics.get_duration_ms() << " ms" << std::endl;
        std::cout << "  Throughput: " << metrics.get_throughput_mbps() 
                  << " Mbps" << std::endl;
    }
    
    void handle_file_download(SecureConnection* conn, 
                            const ProtocolHeader& header) {
        // Receive filename
        std::vector<char> filename_buffer(MAX_FILENAME_LENGTH);
        if (!conn->receive_data(filename_buffer.data(), MAX_FILENAME_LENGTH)) {
            send_error(conn, StatusCode::TRANSFER_ERROR);
            return;
        }
        
        std::string filename(filename_buffer.data());
        filename = "files/" + filename;
        
        std::ifstream file(filename, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            send_error(conn, StatusCode::FILE_NOT_FOUND);
            return;
        }
        
        uint64_t file_size = file.tellg();
        file.seekg(0, std::ios::beg);
        
        std::cout << "Sending file: " << filename 
                  << " (" << file_size << " bytes)" << std::endl;
        
        // Send file size
        conn->send_data(&file_size, sizeof(file_size));
        
        PerformanceMetrics metrics;
        metrics.start();
        
        // Send file data
        std::vector<uint8_t> buffer(BUFFER_SIZE);
        uint64_t sent = 0;
        
        while (sent < file_size) {
            size_t chunk_size = std::min(static_cast<uint64_t>(BUFFER_SIZE), 
                                        file_size - sent);
            
            file.read(reinterpret_cast<char*>(buffer.data()), chunk_size);
            
            if (!conn->send_data(buffer.data(), chunk_size)) {
                file.close();
                return;
            }
            
            sent += chunk_size;
            metrics.add_bytes(chunk_size);
        }
        
        file.close();
        metrics.end();
        
        std::cout << "Download complete: " << filename << std::endl;
        std::cout << "  Duration: " << metrics.get_duration_ms() << " ms" << std::endl;
        std::cout << "  Throughput: " << metrics.get_throughput_mbps() 
                  << " Mbps" << std::endl;
    }
    
    void send_error(SecureConnection* conn, StatusCode code) {
        ProtocolHeader header;
        header.type = MessageType::ERROR_MSG;
        header.payload_length = sizeof(StatusCode);
        header.sequence_number = conn->get_next_sequence();
        
        conn->send_header(header);
        conn->send_data(&code, sizeof(code));
    }
    
public:
    SecureDropServer(int server_port, const std::string& cert, 
                    const std::string& key)
        : server_socket(-1), port(server_port), cert_file(cert), 
          key_file(key), running(false) {}
    
    ~SecureDropServer() {
        stop();
    }
    
    void start() {
        std::cout << "SecureDrop Server v1.0 by Michael Semera" << std::endl;
        std::cout << "Initializing secure server on port " << port << "..." << std::endl;
        
        // Create SSL context
        ssl_context = security_manager.create_server_context();
        security_manager.load_certificates(cert_file, key_file);
        
        // Create and configure socket
        server_socket = create_socket();
        bind_socket(server_socket);
        
        if (listen(server_socket, MAX_CONNECTIONS) < 0) {
            throw SecureDropException("Failed to listen on socket");
        }
        
        running = true;
        std::cout << "Server started successfully. Waiting for connections..." 
                  << std::endl;
        
        // Accept connections
        while (running) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            
            int client_socket = accept(server_socket, 
                                      (struct sockaddr*)&client_addr, 
                                      &client_len);
            
            if (client_socket < 0) {
                if (running) {
                    std::cerr << "Failed to accept connection" << std::endl;
                }
                continue;
            }
            
            std::cout << "New connection from " 
                      << inet_ntoa(client_addr.sin_addr) << std::endl;
            
            // Create SSL connection
            SSL* ssl = SSL_new(ssl_context);
            SSL_set_fd(ssl, client_socket);
            
            if (SSL_accept(ssl) <= 0) {
                std::cerr << "SSL handshake failed" << std::endl;
                SSL_free(ssl);
                close(client_socket);
                continue;
            }
            
            std::cout << "SSL handshake successful" << std::endl;
            
            auto conn = std::make_unique<SecureConnection>(ssl, client_socket);
            handle_client(std::move(conn));
        }
    }
    
    void stop() {
        running = false;
        if (server_socket >= 0) {
            close(server_socket);
            server_socket = -1;
        }
    }
};

/*
 * SecureDropClient - Client implementation
 */
class SecureDropClient {
private:
    SecurityManager security_manager;
    SSL_CTX* ssl_context;
    std::string server_host;
    int server_port;
    
public:
    SecureDropClient(const std::string& host, int port)
        : server_host(host), server_port(port) {
        ssl_context = security_manager.create_client_context();
    }
    
    std::unique_ptr<SecureConnection> connect() {
        std::cout << "Connecting to " << server_host << ":" 
                  << server_port << "..." << std::endl;
        
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            throw SecureDropException("Failed to create socket");
        }
        
        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(server_port);
        
        if (inet_pton(AF_INET, server_host.c_str(), 
                     &server_addr.sin_addr) <= 0) {
            close(sock);
            throw SecureDropException("Invalid address");
        }
        
        if (::connect(sock, (struct sockaddr*)&server_addr, 
                    sizeof(server_addr)) < 0) {
            close(sock);
            throw SecureDropException("Connection failed");
        }
        
        SSL* ssl = SSL_new(ssl_context);
        SSL_set_fd(ssl, sock);
        
        if (SSL_connect(ssl) <= 0) {
            SSL_free(ssl);
            close(sock);
            throw SecureDropException("SSL handshake failed");
        }
        
        std::cout << "Secure connection established" << std::endl;
        return std::make_unique<SecureConnection>(ssl, sock);
    }
    
    bool upload_file(SecureConnection* conn, const std::string& filepath) {
        std::ifstream file(filepath, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            std::cerr << "Failed to open file: " << filepath << std::endl;
            return false;
        }
        
        uint64_t file_size = file.tellg();
        file.seekg(0, std::ios::beg);
        
        // Extract filename
        size_t pos = filepath.find_last_of("/\\");
        std::string filename = (pos != std::string::npos) ? 
                              filepath.substr(pos + 1) : filepath;
        
        std::cout << "Uploading: " << filename 
                  << " (" << file_size << " bytes)" << std::endl;
        
        // Send upload request
        ProtocolHeader header;
        header.type = MessageType::FILE_UPLOAD;
        header.payload_length = MAX_FILENAME_LENGTH + sizeof(uint64_t);
        header.sequence_number = conn->get_next_sequence();
        
        if (!conn->send_header(header)) {
            return false;
        }
        
        // Send filename
        std::vector<char> filename_buffer(MAX_FILENAME_LENGTH, 0);
        strncpy(filename_buffer.data(), filename.c_str(), MAX_FILENAME_LENGTH - 1);
        conn->send_data(filename_buffer.data(), MAX_FILENAME_LENGTH);
        
        // Send file size
        conn->send_data(&file_size, sizeof(file_size));
        
        PerformanceMetrics metrics;
        metrics.start();
        
        // Send file data
        std::vector<uint8_t> buffer(BUFFER_SIZE);
        uint64_t sent = 0;
        
        while (sent < file_size) {
            size_t chunk_size = std::min(static_cast<uint64_t>(BUFFER_SIZE), 
                                        file_size - sent);
            
            file.read(reinterpret_cast<char*>(buffer.data()), chunk_size);
            
            if (!conn->send_data(buffer.data(), chunk_size)) {
                file.close();
                return false;
            }
            
            sent += chunk_size;
            metrics.add_bytes(chunk_size);
            
            // Progress indicator
            int progress = (sent * 100) / file_size;
            std::cout << "\rProgress: " << progress << "%" << std::flush;
        }
        
        file.close();
        metrics.end();
        
        // Wait for completion response
        ProtocolHeader response;
        conn->receive_header(response);
        
        std::cout << "\nUpload complete!" << std::endl;
        std::cout << "Duration: " << metrics.get_duration_ms() << " ms" << std::endl;
        std::cout << "Throughput: " << metrics.get_throughput_mbps() 
                  << " Mbps" << std::endl;
        
        return response.type == MessageType::FILE_COMPLETE;
    }
    
    bool download_file(SecureConnection* conn, const std::string& remote_file,
                      const std::string& local_file) {
        std::cout << "Downloading: " << remote_file << std::endl;
        
        // Send download request
        ProtocolHeader header;
        header.type = MessageType::FILE_DOWNLOAD;
        header.payload_length = MAX_FILENAME_LENGTH;
        header.sequence_number = conn->get_next_sequence();
        
        if (!conn->send_header(header)) {
            return false;
        }
        
        // Send filename
        std::vector<char> filename_buffer(MAX_FILENAME_LENGTH, 0);
        strncpy(filename_buffer.data(), remote_file.c_str(), 
               MAX_FILENAME_LENGTH - 1);
        conn->send_data(filename_buffer.data(), MAX_FILENAME_LENGTH);
        
        // Receive file size
        uint64_t file_size;
        if (!conn->receive_data(&file_size, sizeof(file_size))) {
            return false;
        }
        
        std::cout << "File size: " << file_size << " bytes" << std::endl;
        
        PerformanceMetrics metrics;
        metrics.start();
        
        // Receive file data
        std::ofstream file(local_file, std::ios::binary);
        if (!file.is_open()) {
            std::cerr << "Failed to create local file" << std::endl;
            return false;
        }
        
        std::vector<uint8_t> buffer(BUFFER_SIZE);
        uint64_t received = 0;
        
        while (received < file_size) {
            size_t chunk_size = std::min(static_cast<uint64_t>(BUFFER_SIZE), 
                                        file_size - received);
            
            if (!conn->receive_data(buffer.data(), chunk_size)) {
                file.close();
                return false;
            }
            
            file.write(reinterpret_cast<char*>(buffer.data()), chunk_size);
            received += chunk_size;
            metrics.add_bytes(chunk_size);
            
            int progress = (received * 100) / file_size;
            std::cout << "\rProgress: " << progress << "%" << std::flush;
        }
        
        file.close();
        metrics.end();
        
        std::cout << "\nDownload complete!" << std::endl;
        std::cout << "Duration: " << metrics.get_duration_ms() << " ms" << std::endl;
        std::cout << "Throughput: " << metrics.get_throughput_mbps() 
                  << " Mbps" << std::endl;
        
        return true;
    }
};

#endif // SECUREDROP_H