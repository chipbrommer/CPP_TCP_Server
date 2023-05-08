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
		TCP_Server::TCP_Server()
		{
			mTitle = "TCP Server";
			mAddress = "\n";
			mPort = -1;
			mLastError = TcpServerError::NONE;

#ifdef WIN32
			mWsaData = {};
			mSocket = INVALID_SOCKET;
#else
			mSocket = -1;
#endif
		}

		TCP_Server::TCP_Server(const std::string address, const int16_t port)
		{
			if (ValidateIP(address) >= 0)
			{
				mAddress = address;
			}
			else
			{
				mLastError = TcpServerError::BAD_ADDRESS;
			}

			if (ValidatePort(port) == true)
			{
				mPort = port;
			}
			else
			{
				mLastError = TcpServerError::BAD_PORT;
			}

			mTitle = "TCP Server";
			mLastError = TcpServerError::NONE;

#ifdef WIN32
			mWsaData = {};
			mSocket = INVALID_SOCKET;
#else
			mSocket = -1;
#endif
		}

		TCP_Server::~TCP_Server()
		{
			Stop();
		}

		int8_t TCP_Server::Configure(const std::string address, const int16_t port)
		{
			if (ValidateIP(address) >= 0)
			{
				mAddress = address;
			}
			else
			{
				mLastError = TcpServerError::BAD_ADDRESS;
				return -1;
			}

			if (ValidatePort(port) == true)
			{
				mPort = port;
			}
			else
			{
				mLastError = TcpServerError::BAD_PORT;
				return -1;
			}

			return 0;
		}

		int8_t TCP_Server::Start()
		{
			if (mAddress == "\n" || mAddress.empty())
			{
				mLastError = TcpServerError::ADDRESS_NOT_SET;
				return -1;
			}

			if (mPort == -1)
			{
				mLastError = TcpServerError::PORT_NOT_SET;
				return -1;
			}

#ifdef WIN32
			if (mSocket != INVALID_SOCKET)
			{
				mLastError = TcpServerError::SERVER_ALREADY_STARTED;
				return -1;
			}

			if (WSAStartup(MAKEWORD(2, 2), &mWsaData) != 0)
			{
				mLastError = TcpServerError::WINSOCK_FAILURE;
				return -1;
			}

			mSocket = socket(AF_INET, SOCK_STREAM, 0);

			if (mSocket == INVALID_SOCKET)
			{
				mLastError = TcpServerError::WINDOWS_SOCKET_OPEN_FAILURE;
				WSACleanup();
				return -1;
			}
#else
			if (mSocket != -1)
			{
				mLastError = TcpServerError::SERVER_ALREADY_STARTED;
				return -1;
			}

			mSocket = socket(AF_INET, SOCK_STREAM, 0);

			if (mSocket == -1)
			{
				mLastError = TcpServerError::LINUX_SOCKET_OPEN_FAILURE;
				return 1;
			}
#endif
			// Set up server details
			sockaddr_in serverAddress{};
			serverAddress.sin_family = AF_INET;
			serverAddress.sin_port = htons(mPort);
			if (inet_pton(AF_INET, mAddress.c_str(), &(serverAddress.sin_addr)) <= 0)
			{
				mLastError = TcpServerError::ADDRESS_NOT_SUPPORTED;
				return -1;
			}

			if (bind(mSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) == -1) 
			{
				mLastError = TcpServerError::BIND_FAILED;
				return -1;
			}

			// Listen for incoming connections
			if (listen(mSocket, SOMAXCONN) == -1)
			{
				mLastError = TcpServerError::LISTEN_FAILED;
				return -1;
			}

			// Start the monitor thread
			mStopFlag = false;
			mMonitorThread = std::thread(&TCP_Server::Monitor, this);

			return 0;
		}

		void TCP_Server::Stop()
		{
			// Set the stop flag to true to terminate the monitor thread
			mStopFlag = true;

			// Wait for the monitor thread to finish
			if (mMonitorThread.joinable()) 
			{
				mMonitorThread.join();
			}

#ifdef WIN32
			closesocket(mSocket);
			WSACleanup();
			mSocket = INVALID_SOCKET;
#else
			close(mSocket);
			mSocket = -1;
#endif
			std::cout << "Server stopped." << std::endl;
		}

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

		void TCP_Server::Monitor()
		{
			std::vector<std::thread> clientThreads;  // Store client threads

			while (!mStopFlag) 
			{
				sockaddr_in clientAddress{};
				socklen_t clientAddressLength = sizeof(clientAddress);
				int32_t clientSocket = accept(mSocket, (struct sockaddr*)&clientAddress, &clientAddressLength);

				if (clientSocket == -1) 
				{
					mLastError = TcpServerError::ACCEPT_FAILED;
					continue;
				}

				// Convert client IP address to string
				char clientIP[INET_ADDRSTRLEN];
				inet_ntop(AF_INET, &(clientAddress.sin_addr), clientIP, INET_ADDRSTRLEN);

				// Print notification
				std::cout << "New client connected: " << clientIP << std::endl;

				// Handle the client connection in a separate thread
				std::thread clientThread(&TCP_Server::HandleClient, this, clientSocket, clientIP);
				clientThreads.push_back(std::move(clientThread));

				// Clean up finished client threads
				CleanUpClientThreads(clientThreads);
			}

			// Wait for all client threads to finish
			for (auto& thread : clientThreads) 
			{
				thread.join();
			}
		}

		void TCP_Server::HandleClient(int32_t clientSocket, const std::string& clientIP)
		{
			char buffer[1024];
			int bytesRead;

			// Receive and process client messages
			while ((bytesRead = recv(clientSocket, buffer, sizeof(buffer) - 1, 0)) > 0) 
			{
				// Null-terminate the received data
				buffer[bytesRead] = '\0';

				// Display the received message
				std::cout << "Received from client " << clientIP << ": " << buffer << std::endl;

				// Echo back the message to the client
				if (send(clientSocket, buffer, bytesRead, 0) == -1) 
				{
					mLastError = TcpServerError::ECHO_FAILED;
					break;
				}
			}

			if (bytesRead == 0) 
			{
				// Client disconnected
				std::cout << "Client disconnected: " << clientIP << std::endl;
			}
			else if (bytesRead == -1) 
			{
				// Error receiving data
				std::cerr << "Error receiving data from client " << clientIP << std::endl;
			}

#ifdef WIN32
			closesocket(clientSocket);
#else
			close(clientSocket);
#endif
		}

		void TCP_Server::CleanUpClientThreads(std::vector<std::thread>& clientThreads)
		{
			for (auto it = clientThreads.begin(); it != clientThreads.end();) 
			{
				if (it->joinable()) 
				{
					it->join();
					it = clientThreads.erase(it);
				}
				else 
				{
					++it;
				}
			}
		}
	}
}