/*
 * SecureDrop Performance Benchmark
 * Author: Michael Semera
 * 
 * Compares SecureDrop performance with SFTP baseline
 * Usage: ./benchmark <host> <port> <test_file_size_mb>
 */

#include "securedrop.h"
#include <random>
#include <fstream>
#include <iomanip>

class BenchmarkRunner {
private:
    std::string host;
    int port;
    
    void generate_test_file(const std::string& filename, size_t size_mb) {
        std::cout << "Generating " << size_mb << "MB test file..." << std::endl;
        
        std::ofstream file(filename, std::ios::binary);
        if (!file.is_open()) {
            throw SecureDropException("Failed to create test file");
        }
        
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        
        const size_t chunk_size = 1024 * 1024; // 1MB chunks
        std::vector<uint8_t> buffer(chunk_size);
        
        for (size_t i = 0; i < size_mb; i++) {
            for (size_t j = 0; j < chunk_size; j++) {
                buffer[j] = static_cast<uint8_t>(dis(gen));
            }
            file.write(reinterpret_cast<char*>(buffer.data()), chunk_size);
        }
        
        file.close();
        std::cout << "Test file created successfully" << std::endl;
    }
    
    double benchmark_securedrop_upload(const std::string& filename) {
        std::cout << "\n--- SecureDrop Upload Benchmark ---" << std::endl;
        
        SecureDropClient client(host, port);
        auto connection = client.connect();
        
        auto start = std::chrono::high_resolution_clock::now();
        
        bool success = client.upload_file(connection.get(), filename);
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            end - start).count();
        
        if (!success) {
            throw SecureDropException("Upload failed");
        }
        
        // Send disconnect
        ProtocolHeader disconnect;
        disconnect.type = MessageType::DISCONNECT;
        disconnect.payload_length = 0;
        disconnect.sequence_number = connection->get_next_sequence();
        connection->send_header(disconnect);
        
        return duration / 1000.0;
    }
    
    double benchmark_securedrop_download(const std::string& remote_file,
                                        const std::string& local_file) {
        std::cout << "\n--- SecureDrop Download Benchmark ---" << std::endl;
        
        SecureDropClient client(host, port);
        auto connection = client.connect();
        
        auto start = std::chrono::high_resolution_clock::now();
        
        bool success = client.download_file(connection.get(), remote_file, 
                                           local_file);
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            end - start).count();
        
        if (!success) {
            throw SecureDropException("Download failed");
        }
        
        // Send disconnect
        ProtocolHeader disconnect;
        disconnect.type = MessageType::DISCONNECT;
        disconnect.payload_length = 0;
        disconnect.sequence_number = connection->get_next_sequence();
        connection->send_header(disconnect);
        
        return duration / 1000.0;
    }
    
public:
    BenchmarkRunner(const std::string& server_host, int server_port)
        : host(server_host), port(server_port) {}
    
    void run_benchmark(size_t file_size_mb) {
        std::cout << "============================================" << std::endl;
        std::cout << "   SecureDrop Performance Benchmark" << std::endl;
        std::cout << "   Author: Michael Semera" << std::endl;
        std::cout << "============================================" << std::endl;
        std::cout << std::endl;
        
        std::string test_file = "benchmark_test.bin";
        std::string downloaded_file = "benchmark_downloaded.bin";
        
        try {
            // Generate test file
            generate_test_file(test_file, file_size_mb);
            
            // Benchmark upload
            double upload_time = benchmark_securedrop_upload(test_file);
            double upload_throughput = (file_size_mb * 8.0) / upload_time;
            
            // Benchmark download
            double download_time = benchmark_securedrop_download(test_file, 
                                                                downloaded_file);
            double download_throughput = (file_size_mb * 8.0) / download_time;
            
            // Display results
            std::cout << "\n============================================" 
                      << std::endl;
            std::cout << "   BENCHMARK RESULTS" << std::endl;
            std::cout << "============================================" 
                      << std::endl;
            std::cout << std::fixed << std::setprecision(2);
            std::cout << "\nFile Size: " << file_size_mb << " MB" << std::endl;
            std::cout << "\nUpload Performance:" << std::endl;
            std::cout << "  Duration:    " << upload_time << " seconds" 
                      << std::endl;
            std::cout << "  Throughput:  " << upload_throughput << " Mbps" 
                      << std::endl;
            std::cout << "\nDownload Performance:" << std::endl;
            std::cout << "  Duration:    " << download_time << " seconds" 
                      << std::endl;
            std::cout << "  Throughput:  " << download_throughput << " Mbps" 
                      << std::endl;
            
            // SFTP comparison (theoretical estimates)
            std::cout << "\n============================================" 
                      << std::endl;
            std::cout << "   COMPARISON WITH SFTP (Estimated)" << std::endl;
            std::cout << "============================================" 
                      << std::endl;
            
            // Typical SFTP performance: 20-50 MB/s on gigabit networks
            double sftp_typical_mbps = 300; // ~37.5 MB/s
            double sftp_time = (file_size_mb * 8.0) / sftp_typical_mbps;
            
            std::cout << "\nTypical SFTP Performance:" << std::endl;
            std::cout << "  Throughput:  " << sftp_typical_mbps << " Mbps (estimated)" 
                      << std::endl;
            std::cout << "  Duration:    " << sftp_time << " seconds (estimated)" 
                      << std::endl;
            
            std::cout << "\nSecureDrop vs SFTP:" << std::endl;
            double upload_diff = ((upload_throughput - sftp_typical_mbps) / 
                                 sftp_typical_mbps) * 100;
            double download_diff = ((download_throughput - sftp_typical_mbps) / 
                                   sftp_typical_mbps) * 100;
            
            std::cout << "  Upload:   " << (upload_diff > 0 ? "+" : "") 
                      << upload_diff << "%" << std::endl;
            std::cout << "  Download: " << (download_diff > 0 ? "+" : "") 
                      << download_diff << "%" << std::endl;
            
            std::cout << "\nKey Advantages of SecureDrop:" << std::endl;
            std::cout << "  ✓ Custom protocol optimized for bulk transfers" 
                      << std::endl;
            std::cout << "  ✓ Reduced protocol overhead vs SFTP" << std::endl;
            std::cout << "  ✓ Streaming architecture with large buffers" 
                      << std::endl;
            std::cout << "  ✓ TLS 1.3 encryption for security" << std::endl;
            std::cout << "  ✓ Real-time progress monitoring" << std::endl;
            std::cout << "  ✓ Integrated integrity verification" << std::endl;
            
            // Cleanup
            remove(test_file.c_str());
            remove(downloaded_file.c_str());
            
        } catch (const std::exception& e) {
            std::cerr << "Benchmark error: " << e.what() << std::endl;
            remove(test_file.c_str());
            remove(downloaded_file.c_str());
            throw;
        }
    }
};

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cout << "Usage: " << argv[0] 
                  << " <host> <port> <test_file_size_mb>" << std::endl;
        std::cout << "Example: " << argv[0] << " 127.0.0.1 8443 100" 
                  << std::endl;
        return 1;
    }
    
    std::string host = argv[1];
    int port = std::atoi(argv[2]);
    size_t file_size_mb = std::atoi(argv[3]);
    
    if (file_size_mb < 1 || file_size_mb > 10000) {
        std::cerr << "File size must be between 1 and 10000 MB" << std::endl;
        return 1;
    }
    
    try {
        BenchmarkRunner benchmark(host, port);
        benchmark.run_benchmark(file_size_mb);
        
        std::cout << "\n✓ Benchmark completed successfully!" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}