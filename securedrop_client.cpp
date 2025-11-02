/*
 * SecureDrop Client Application
 * Author: Michael Semera
 * 
 * Usage: 
 *   Upload:   ./securedrop_client <host> <port> upload <file>
 *   Download: ./securedrop_client <host> <port> download <remote_file> <local_file>
 */

#include "securedrop.h"

void print_usage(const char* program_name) {
    std::cout << "SecureDrop Client v1.0 by Michael Semera\n" << std::endl;
    std::cout << "Usage:" << std::endl;
    std::cout << "  Upload:   " << program_name 
              << " <host> <port> upload <file>" << std::endl;
    std::cout << "  Download: " << program_name 
              << " <host> <port> download <remote_file> <local_file>" << std::endl;
    std::cout << "\nExamples:" << std::endl;
    std::cout << "  " << program_name << " 127.0.0.1 8443 upload document.pdf" 
              << std::endl;
    std::cout << "  " << program_name 
              << " 127.0.0.1 8443 download document.pdf downloaded.pdf" 
              << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 5) {
        print_usage(argv[0]);
        return 1;
    }
    
    std::string host = argv[1];
    int port = std::atoi(argv[2]);
    std::string operation = argv[3];
    
    std::cout << "============================================" << std::endl;
    std::cout << "   SecureDrop Client v1.0" << std::endl;
    std::cout << "   Author: Michael Semera" << std::endl;
    std::cout << "============================================" << std::endl;
    std::cout << std::endl;
    
    try {
        SecureDropClient client(host, port);
        auto connection = client.connect();
        
        if (operation == "upload") {
            if (argc < 5) {
                std::cerr << "Error: Missing filename for upload" << std::endl;
                return 1;
            }
            
            std::string filename = argv[4];
            
            if (client.upload_file(connection.get(), filename)) {
                std::cout << "✓ File uploaded successfully" << std::endl;
            } else {
                std::cerr << "✗ Upload failed" << std::endl;
                return 1;
            }
            
        } else if (operation == "download") {
            if (argc < 6) {
                std::cerr << "Error: Missing filenames for download" << std::endl;
                return 1;
            }
            
            std::string remote_file = argv[4];
            std::string local_file = argv[5];
            
            if (client.download_file(connection.get(), remote_file, local_file)) {
                std::cout << "✓ File downloaded successfully" << std::endl;
            } else {
                std::cerr << "✗ Download failed" << std::endl;
                return 1;
            }
            
        } else {
            std::cerr << "Error: Unknown operation '" << operation << "'" << std::endl;
            print_usage(argv[0]);
            return 1;
        }
        
        // Send disconnect message
        ProtocolHeader disconnect;
        disconnect.type = MessageType::DISCONNECT;
        disconnect.payload_length = 0;
        disconnect.sequence_number = connection->get_next_sequence();
        connection->send_header(disconnect);
        
    } catch (const SecureDropException& e) {
        std::cerr << "Client error: " << e.what() << std::endl;
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Unexpected error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}