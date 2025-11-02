# SecureDrop Makefile
# Author: Michael Semera

CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O3 -pthread
LDFLAGS = -lssl -lcrypto

# Target executables
SERVER = securedrop_server
CLIENT = securedrop_client
BENCHMARK = securedrop_benchmark

# Source files
SERVER_SRC = server_main.cpp
CLIENT_SRC = client_main.cpp
BENCHMARK_SRC = benchmark.cpp

# Default target
all: $(SERVER) $(CLIENT) $(BENCHMARK)

# Build server
$(SERVER): $(SERVER_SRC) securedrop.h
	$(CXX) $(CXXFLAGS) $(SERVER_SRC) -o $(SERVER) $(LDFLAGS)
	@echo "✓ Server built successfully"

# Build client
$(CLIENT): $(CLIENT_SRC) securedrop.h
	$(CXX) $(CXXFLAGS) $(CLIENT_SRC) -o $(CLIENT) $(LDFLAGS)
	@echo "✓ Client built successfully"

# Build benchmark tool
$(BENCHMARK): $(BENCHMARK_SRC) securedrop.h
	$(CXX) $(CXXFLAGS) $(BENCHMARK_SRC) -o $(BENCHMARK) $(LDFLAGS)
	@echo "✓ Benchmark tool built successfully"

# Generate test SSL certificates
certs:
	@echo "Generating SSL certificates..."
	@openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt \
		-days 365 -nodes -subj "/CN=localhost"
	@echo "✓ Certificates generated (server.crt, server.key)"

# Setup directories
setup:
	@mkdir -p uploads files logs
	@echo "✓ Directories created"

# Clean build artifacts
clean:
	rm -f $(SERVER) $(CLIENT) $(BENCHMARK)
	rm -f *.o
	@echo "✓ Build artifacts cleaned"

# Deep clean (including certificates and uploads)
distclean: clean
	rm -f server.crt server.key
	rm -rf uploads/* files/* logs/*
	@echo "✓ Full cleanup completed"

# Install (copy to /usr/local/bin)
install: all
	@echo "Installing SecureDrop..."
	@sudo cp $(SERVER) /usr/local/bin/
	@sudo cp $(CLIENT) /usr/local/bin/
	@sudo cp $(BENCHMARK) /usr/local/bin/
	@echo "✓ Installed to /usr/local/bin/"

# Uninstall
uninstall:
	@sudo rm -f /usr/local/bin/$(SERVER)
	@sudo rm -f /usr/local/bin/$(CLIENT)
	@sudo rm -f /usr/local/bin/$(BENCHMARK)
	@echo "✓ Uninstalled from /usr/local/bin/"

# Run tests
test: all certs setup
	@echo "Starting server in background..."
	@./$(SERVER) 8443 server.crt server.key &
	@sleep 2
	@echo "Creating test file..."
	@dd if=/dev/urandom of=test_file.bin bs=1M count=10 2>/dev/null
	@echo "Running upload test..."
	@./$(CLIENT) 127.0.0.1 8443 upload test_file.bin
	@echo "Running download test..."
	@./$(CLIENT) 127.0.0.1 8443 download test_file.bin downloaded_test.bin
	@echo "Comparing files..."
	@diff test_file.bin downloaded_test.bin && echo "✓ Files match!" || echo "✗ Files differ!"
	@rm -f test_file.bin downloaded_test.bin
	@pkill -f $(SERVER)
	@echo "✓ Tests completed"

# Quick start (build, setup, and generate certs)
quickstart: all certs setup
	@echo ""
	@echo "============================================"
	@echo "   SecureDrop is ready!"
	@echo "============================================"
	@echo ""
	@echo "Start server: ./$(SERVER) 8443 server.crt server.key"
	@echo "Upload file:  ./$(CLIENT) 127.0.0.1 8443 upload myfile.txt"
	@echo "Download:     ./$(CLIENT) 127.0.0.1 8443 download myfile.txt local.txt"
	@echo "Benchmark:    ./$(BENCHMARK) 127.0.0.1 8443 100"
	@echo ""

# Help target
help:
	@echo "SecureDrop Build System"
	@echo "Author: Michael Semera"
	@echo ""
	@echo "Available targets:"
	@echo "  make              - Build all components"
	@echo "  make server       - Build server only"
	@echo "  make client       - Build client only"
	@echo "  make benchmark    - Build benchmark tool only"
	@echo "  make certs        - Generate SSL certificates"
	@echo "  make setup        - Create necessary directories"
	@echo "  make quickstart   - Build everything and setup"
	@echo "  make test         - Run automated tests"
	@echo "  make clean        - Remove build artifacts"
	@echo "  make distclean    - Full cleanup"
	@echo "  make install      - Install to system"
	@echo "  make uninstall    - Remove from system"
	@echo "  make help         - Show this help message"

.PHONY: all clean distclean certs setup install uninstall test quickstart help