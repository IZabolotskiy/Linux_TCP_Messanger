#include <iostream>
#include <thread>
#include <vector>
#include <string>
#include <chrono>
#include <iomanip>
#include <ctime>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <cstring>
#include <mutex>
#include <fstream>


class SocketBase {
protected:
    int sockfd;
    sockaddr_in addr;

public:
    SocketBase() : sockfd(-1) {}

    void createSocket() {
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd == -1) {
            perror("Socket creation failed");
            exit(EXIT_FAILURE);
        }
    }

    void bindSocket(int port) {
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);

        if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
            perror("Socket binding failed");
            close(sockfd);
            exit(EXIT_FAILURE);
        }
    }

    void connectToServer(const std::string& serverIP, int port) {
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);

        if (inet_pton(AF_INET, serverIP.c_str(), &addr.sin_addr) <= 0) {
            perror("Invalid address/ Address not supported");
            exit(EXIT_FAILURE);
        }

        if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            perror("Connection failed");
            exit(EXIT_FAILURE);
        }
    }

    int getSocket() const { return sockfd; }

    virtual ~SocketBase() {
        if (sockfd != -1) {
            close(sockfd);
        }
    }
};

class Server : public SocketBase {
private:
    std::vector<std::thread> clientThreads;
    std::mutex mtx;
    std::ofstream logFile;

    void handleClient(int clientSocket) {
        char buffer[1024] = {0};
        while (true) {
            int valread = read(clientSocket, buffer, sizeof(buffer) - 1);
            if (valread <= 0) {
                std::cout << "Client disconnected\n";
                close(clientSocket);
                break;
            }
            buffer[valread] = '\0';

            
            std::lock_guard<std::mutex> lock(mtx);
            std::string message(buffer);
            std::cout << message << std::endl;
            logMessage(message);
        }
    }

    void logMessage(const std::string& message) {
        if (logFile.is_open()) {
            logFile << message << std::endl;
        }
    }

public:
    Server() {
       
        logFile.open("Log.txt", std::ios::app);
        if (!logFile) {
            std::cerr << "Failed to open log file." << std::endl;
            exit(EXIT_FAILURE);
        }
    }

    void startServer(int port) {
        createSocket();
        bindSocket(port);

        if (listen(sockfd, 5) == -1) {
            perror("Listen failed");
            exit(EXIT_FAILURE);
        }


        while (true) {
            int clientSocket = accept(sockfd, NULL, NULL);
            if (clientSocket < 0) {
                perror("Client connection failed");
                exit(EXIT_FAILURE);
            }
            clientThreads.push_back(std::thread(&Server::handleClient, this, clientSocket));
        }
    }

    ~Server() {
        for (auto& th : clientThreads) {
            if (th.joinable()) {
                th.join();
            }
        }
        if (logFile.is_open()) {
            logFile.close();
        }
    }
};

class Client : public SocketBase {
private:
    std::string clientName;
    int period;

    std::string get_current_timestamp() {
    
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

    std::tm buf;
    localtime_r(&in_time_t, &buf);
    char time_buffer[100];
    std::strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", &buf);
    
    std::stringstream ss;
    ss << time_buffer << "." << std::setfill('0') << std::setw(3) << milliseconds.count();

    return ss.str();
}

public:
    Client(const std::string& name, int periodInSec) : clientName(name), period(periodInSec) {}

    void startClient(int port) {
        const std::string& serverIP="127.0.0.1";
        createSocket();
        connectToServer(serverIP, port);

        while (true) {
            std::string message = "[" + get_current_timestamp() + "] " + clientName;
            send(sockfd, message.c_str(), message.length(), 0);
            std::this_thread::sleep_for(std::chrono::seconds(period));
        }
    }
};

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: \n"
                  << "Server: " << argv[0] << " server <port>\n"
                  << "Client: " << argv[0] << " client <name> <port> <period>\n";
        return EXIT_FAILURE;
    }

    std::string mode = argv[1];
    if (mode == "server") {
        if (argc != 3) {
            std::cerr << "Usage: " << argv[0] << " server <port>\n";
            return EXIT_FAILURE;
        }
        int port = std::stoi(argv[2]);
        Server server;
        server.startServer(port);
    } else if (mode == "client") {
        if (argc != 5) {
            std::cerr << "Usage: " << argv[0] << " client <name> <port> <period>\n";
            return EXIT_FAILURE;
        }
        std::string clientName = argv[2];
        int port = std::stoi(argv[3]);
        int period = std::stoi(argv[4]);

        Client client(clientName, period);
        client.startClient(port);
    } else {
        std::cerr << "Invalid mode! Use 'server' or 'client'.\n";
        return EXIT_FAILURE;
    }

    return 0;
}
