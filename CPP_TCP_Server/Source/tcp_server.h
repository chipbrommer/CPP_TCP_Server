///////////////////////////////////////////////////////////////////////////////
//!
//! @file		tcp_server.h
//! 
//! @brief		A cross platform class to spawn a tcp server.
//! 
//! @author		Chip Brommer
//! 
//! @date		< 04 / 30 / 2023 > Initial Start Date
//!
/*****************************************************************************/
#pragma once
///////////////////////////////////////////////////////////////////////////////
//
//  Includes:
//          name                        reason included
//          --------------------        ---------------------------------------
#ifdef WIN32
#include <stdint.h>						// Standard integer types
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif
#include <map>							// Error enum to strings.
#include <string>						// Strings
#include <regex>						// Regular expression for ip validation
#include <thread>						// Multiple threads for monitor and clients. 
#include <atomic>						// Thread instance stop flag
#include <vector>						// Client thread list 
#include <iostream>						// Prints 
//
//	Defines:
//          name                        reason defined
//          --------------------        ---------------------------------------
#ifndef     CPP_TCP_SERVER				// Define the cpp tcp server class. 
#define     CPP_TCP_SERVER
//
///////////////////////////////////////////////////////////////////////////////

namespace Essentials
{
	namespace Communications
	{
		constexpr static uint8_t TCP_SERVER_VERSION_MAJOR = 0;
		constexpr static uint8_t TCP_SERVER_VERSION_MINOR = 1;
		constexpr static uint8_t TCP_SERVER_VERSION_PATCH = 0;
		constexpr static uint8_t TCP_SERVER_VERSION_BUILD = 0;

		static std::string TcpServerVersion = "TCP Server v" +
			std::to_string((uint8_t)TCP_SERVER_VERSION_MAJOR) + "." +
			std::to_string((uint8_t)TCP_SERVER_VERSION_MINOR) + "." +
			std::to_string((uint8_t)TCP_SERVER_VERSION_PATCH) + " - b" +
			std::to_string((uint8_t)TCP_SERVER_VERSION_BUILD) + ".\n";

		/// <summary>enum for error codes</summary>
		enum class TcpServerError : uint8_t
		{
			NONE,
			BAD_ADDRESS,
			ADDRESS_NOT_SET,
			BAD_PORT,
			PORT_NOT_SET,
			SERVER_ALREADY_STARTED,
			FAILED_TO_CONNECT,
			WINSOCK_FAILURE,
			WINDOWS_SOCKET_OPEN_FAILURE,
			LINUX_SOCKET_OPEN_FAILURE,
			ADDRESS_NOT_SUPPORTED,
			BIND_FAILED,
			LISTEN_FAILED,
			CONNECTION_FAILED,
			ACCEPT_FAILED,
			ECHO_FAILED,
			RECEIVE_FAILED,
		};

		/// <summary>Error enum to string map</summary>
		static std::map<TcpServerError, std::string> TcpServerErrorMap
		{
			{TcpServerError::NONE,
			std::string("Error Code " + std::to_string((uint8_t)TcpServerError::NONE) + ": No error.")},
			{TcpServerError::BAD_ADDRESS,
			std::string("Error Code " + std::to_string((uint8_t)TcpServerError::BAD_ADDRESS) + ": Bad address.")},
			{TcpServerError::ADDRESS_NOT_SET,
			std::string("Error Code " + std::to_string((uint8_t)TcpServerError::ADDRESS_NOT_SET) + ": Address not set.")},
			{TcpServerError::BAD_PORT,
			std::string("Error Code " + std::to_string((uint8_t)TcpServerError::BAD_PORT) + ": Bad port.")},
			{TcpServerError::PORT_NOT_SET,
			std::string("Error Code " + std::to_string((uint8_t)TcpServerError::PORT_NOT_SET) + ": Port not set.")},
			{TcpServerError::SERVER_ALREADY_STARTED,
			std::string("Error Code " + std::to_string((uint8_t)TcpServerError::SERVER_ALREADY_STARTED) + ": Server already started.")},
			{TcpServerError::FAILED_TO_CONNECT,
			std::string("Error Code " + std::to_string((uint8_t)TcpServerError::FAILED_TO_CONNECT) + ": Failed to connect.")},
			{TcpServerError::WINSOCK_FAILURE,
			std::string("Error Code " + std::to_string((uint8_t)TcpServerError::WINSOCK_FAILURE) + ": Winsock creation failure.")},
			{TcpServerError::WINDOWS_SOCKET_OPEN_FAILURE,
			std::string("Error Code " + std::to_string((uint8_t)TcpServerError::WINDOWS_SOCKET_OPEN_FAILURE) + ": Socket open failure.")},
			{TcpServerError::LINUX_SOCKET_OPEN_FAILURE,
			std::string("Error Code " + std::to_string((uint8_t)TcpServerError::LINUX_SOCKET_OPEN_FAILURE) + ": Socket open failure.")},
			{TcpServerError::ADDRESS_NOT_SUPPORTED,
			std::string("Error Code " + std::to_string((uint8_t)TcpServerError::ADDRESS_NOT_SUPPORTED) + ": Address not supported.")},
			{TcpServerError::BIND_FAILED,
			std::string("Error Code " + std::to_string((uint8_t)TcpServerError::BIND_FAILED) + ": Binding to socket failed.")},
			{TcpServerError::LISTEN_FAILED,
			std::string("Error Code " + std::to_string((uint8_t)TcpServerError::LISTEN_FAILED) + ": Listener setup failed.")},
			{TcpServerError::CONNECTION_FAILED,
			std::string("Error Code " + std::to_string((uint8_t)TcpServerError::CONNECTION_FAILED) + ": Connection failed.")},
			{TcpServerError::ACCEPT_FAILED,
			std::string("Error Code " + std::to_string((uint8_t)TcpServerError::ACCEPT_FAILED) + ": Accepting new client failed.")},
			{TcpServerError::ECHO_FAILED,
			std::string("Error Code " + std::to_string((uint8_t)TcpServerError::ECHO_FAILED) + ": Echo to client failed.")},
			{TcpServerError::RECEIVE_FAILED,
			std::string("Error Code " + std::to_string((uint8_t)TcpServerError::RECEIVE_FAILED) + ": Receive from client failed.")},
		};

		/// <summary>A class to spawn a TCP server on multiple platform types.</summary>
		class TCP_Server
		{
		public:
			TCP_Server();
			TCP_Server(const std::string address, const int16_t port);
			~TCP_Server();
			int8_t Configure(const std::string address, const int16_t port);
			int8_t Start();
			void Stop();
			
			/// <summary>Get the last error in string format</summary>
			/// <returns>The last error in a formatted string</returns>
			std::string GetLastError();

		protected:
		private:
			/// <summary>Validates an IP address is IPv4 or IPv6</summary>
			/// <param name="ip"> -[in]- IP Address to be validated</param>
			/// <returns>-1 = bad IP, 1 = valid IPv4, 2 = valid IPv6</returns>
			int8_t ValidateIP(const std::string& ip);

			/// <summary>Validates a port number is between 0-99999</summary>
			/// <param name="port"> -[in]- Port number to be validated</param>
			/// <returns>true = valid, false = invalid</returns>
			bool ValidatePort(const int16_t port);


			void Monitor();

			void HandleClient(int32_t clientSocket, const std::string& clientIP);
			void CleanUpClientThreads(std::vector<std::thread>& clientThreads);

			std::string		mTitle;
			std::string		mAddress;
			int16_t			mPort;
			TcpServerError	mLastError;
			std::thread		mMonitorThread;
			std::atomic<bool> mStopFlag;

#ifdef WIN32
			WSADATA				mWsaData;
			SOCKET				mSocket;
#else
			int32_t				mSocket;
#endif
		};
	} // Communications
} // Essentials

#endif // CPP_TCP_SERVER
