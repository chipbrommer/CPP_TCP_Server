///////////////////////////////////////////////////////////////////////////////
//!
//! @file		tcp_server.cpp
//! 
//! @brief		Implementation of the tcp server class
//! 
//! @author		Chip Brommer
//! 
//! @date		< 04 / 30 / 2023 > Initial Start Date
//!
/*****************************************************************************/

///////////////////////////////////////////////////////////////////////////////
//
//  Includes:
//          name                        reason included
//          --------------------        ---------------------------------------
#include	"tcp_server.h"				// TCP Server Class
//
///////////////////////////////////////////////////////////////////////////////

namespace Essentials
{
	namespace Communications
	{





		std::string TCP_Server::GetLastError()
		{
			return TcpServerErrorMap[mLastError];
		}

		int8_t TCP_Server::ValidateIP(const std::string& ip)
		{
			// Regex expression for validating IPv4
			std::regex ipv4("(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])");

			// Regex expression for validating IPv6
			std::regex ipv6("((([0-9a-fA-F]){1,4})\\:){7}([0-9a-fA-F]){1,4}");

			// Checking if it is a valid IPv4 addresses
			if (std::regex_match(ip, ipv4))
			{
				return 1;
			}
			// Checking if it is a valid IPv6 addresses
			else if (std::regex_match(ip, ipv6))
			{
				return 2;
			}

			// Return Invalid
			return -1;
		}

		bool TCP_Server::ValidatePort(const int16_t port)
		{
			return (port > -1 && port < 99999);
		}

}
}

namespace Essentials
{
	namespace Communications
	{
        TCPServer::TCPServer(int port) : port_(port), serverSocket_(-1), monitoringThread_(&TCPServer::MonitorClients, this) {}

        TCPServer::TCPServer(int port, const std::string& ip) : port_(port), ipAddress_(ip), serverSocket_(-1), monitoringThread_(&TCPServer::MonitorClients, this) {}

        TCPServer::~TCPServer() {
            if (serverSocket_ != -1) {
                closesocket(serverSocket_);
            }

            stopMonitoring_ = true;
            if (monitoringThread_.joinable()) {
                monitoringThread_.join();
            }
        }

        void TCPServer::Start() {
            if (InitializeServer()) {
                std::cout << "Server started on port " << port_ << std::endl;
                while (true) {
                    int clientSocket = AcceptConnection();
                    if (clientSocket != -1) {
                        std::thread clientThread(&TCPServer::HandleClient, this, clientSocket);
                        clientThread.detach(); // Detach the thread to allow it to run independently
                    }
                }
            }
            else {
                std::cerr << "Failed to start the server." << std::endl;
            }
        }

        void TCPServer::MonitorClients() {
            while (!stopMonitoring_) {
                std::this_thread::sleep_for(std::chrono::seconds(5)); // Adjust the interval as needed

                // Check and handle client disconnects or perform other monitoring tasks
                CheckClientStatus();
            }
        }

        void TCPServer::ReceiveFileFromClient(int clientSocket) {
            // Receive initial packet containing file information
            char fileInfoBuffer[1024];
            int bytesRead = recv(clientSocket, fileInfoBuffer, sizeof(fileInfoBuffer), 0);

            if (bytesRead <= 0) {
                std::cerr << "Error receiving file information from client." << std::endl;
                return;
            }

            // Parse the received file information
            std::string fileInfo(fileInfoBuffer, bytesRead);
            size_t pos = fileInfo.find(':');
            if (pos == std::string::npos) {
                std::cerr << "Invalid file information format." << std::endl;
                return;
            }

            std::string action = fileInfo.substr(0, pos);
            fileInfo.erase(0, pos + 1);

            pos = fileInfo.find(':');
            if (pos == std::string::npos) {
                std::cerr << "Invalid file information format." << std::endl;
                return;
            }

            std::string fileName = fileInfo.substr(0, pos);
            fileInfo.erase(0, pos + 1);

            size_t fileSize = std::stoul(fileInfo);

            // Process the file based on the action
            if (action == "UPLOAD") {
                std::cout << "Receiving file from client. (Action: " << action << ", File: " << fileName << ", Size: " << fileSize << " bytes)" << std::endl;
                ReceiveFileData(clientSocket, fileName, fileSize);
            }
            else {
                std::cerr << "Unknown file action from client: " << action << std::endl;
            }
        }

        bool TCPServer::InitializeServer() {
            serverSocket_ = socket(AF_INET, SOCK_STREAM, 0);
            if (serverSocket_ == -1) {
                std::cerr << "Error creating server socket." << std::endl;
                return false;
            }

            sockaddr_in serverAddress{};
            serverAddress.sin_family = AF_INET;
            serverAddress.sin_addr.s_addr = INADDR_ANY;
            serverAddress.sin_port = htons(port_);

            if (bind(serverSocket_, reinterpret_cast<struct sockaddr*>(&serverAddress), sizeof(serverAddress)) == -1) {
                std::cerr << "Error binding server socket." << std::endl;
                closesocket(serverSocket_);
                return false;
            }

            if (listen(serverSocket_, 10) == -1) {
                std::cerr << "Error listening on server socket." << std::endl;
                closesocket(serverSocket_);
                return false;
            }

            return true;
        }

        int TCPServer::AcceptConnection() {
            sockaddr_in clientAddress{};
            socklen_t clientAddressLen = sizeof(clientAddress);

            int clientSocket = accept(serverSocket_, reinterpret_cast<struct sockaddr*>(&clientAddress), &clientAddressLen);
            if (clientSocket == -1) {
                std::cerr << "Error accepting connection." << std::endl;
                return -1;
            }

            {
                std::lock_guard<std::mutex> lock(mutex_);
                clients_.push_back(clientSocket);
            }

            std::cout << "Client connected. (Socket: " << clientSocket << ")" << std::endl;

            return clientSocket;
        }

        void TCPServer::HandleClient(int clientSocket) {
            // Example: Receiving a file from the client
            std::string fileName = "received_file.txt"; // Specify the desired file name
            ReceiveFileFromClient(clientSocket);
        }

        void TCPServer::CheckClientStatus() {
            std::lock_guard<std::mutex> lock(mutex_);
            for (auto it = clients_.begin(); it != clients_.end();) {
                int clientSocket = *it;
                char dummyBuffer[1];
                int result = recv(clientSocket, dummyBuffer, sizeof(dummyBuffer), MSG_PEEK);

                if (result == 0 || (result == -1 && errno == ECONNRESET)) {
                    // Connection closed or reset by the client
                    std::cout << "Client disconnected. (Socket: " << clientSocket << ")" << std::endl;
                    closesocket(clientSocket);
                    it = clients_.erase(it);
                }
                else {
                    ++it;
                }
            }

            // Perform other monitoring tasks as needed
        }

        void TCPServer::ReceiveFileData(int clientSocket, const std::string& fileName, size_t fileSize) {
            std::ofstream outputFile(fileName, std::ios::out | std::ios::binary);
            if (!outputFile.is_open()) {
                std::cerr << "Error opening file for writing: " << fileName << std::endl;
                return;
            }

            char buffer[1024];
            size_t totalBytesReceived = 0;
            const int timeoutSeconds = 10; 
            size_t percentageThreshold = 10;

            while (totalBytesReceived < fileSize) {
                auto startTime = std::chrono::steady_clock::now();

                int bytesRead = recv(clientSocket, buffer, sizeof(buffer), 0);
                if (bytesRead <= 0) {
                    std::cerr << "Error receiving file data from client." << std::endl;
                    break;
                }

                outputFile.write(buffer, bytesRead);
                totalBytesReceived += bytesRead;

                auto endTime = std::chrono::steady_clock::now();
                auto elapsedSeconds = std::chrono::duration_cast<std::chrono::seconds>(endTime - startTime).count();

                if (elapsedSeconds > timeoutSeconds) {
                    std::cerr << "Timeout: File data not received within " << timeoutSeconds << " seconds." << std::endl;
                    break;
                }

                // Check percentage of received data
                size_t percentageReceived = (totalBytesReceived * 100) / fileSize;
                if (percentageReceived > percentageThreshold) {
                    std::cout << "Received " << percentageReceived << "% of file data." << std::endl;
                    percentageThreshold += 10; // Adjust the threshold increment as needed
                }
            }

            outputFile.close();
            std::cout << "File received from client. (File: " << fileName << ", Size: " << totalBytesReceived << " bytes)" << std::endl;
        }

	}
}