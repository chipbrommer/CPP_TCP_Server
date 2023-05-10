
#include <iostream>
#include "Source/tcp_server.h"

int main()
{
	std::cout << "Hello CMake." << std::endl;
	
    std::string ipAddress = "127.0.0.1";  // Example IP address
    int16_t port = 8080;  // Example port

    Essentials::Communications::TCP_Server server(ipAddress, port);
    std::cout << Essentials::Communications::TcpServerVersion;

    if (server.Start() < 0) 
    {
        std::cerr << "Failed to start the server." << std::endl;
        std::cout << server.GetLastError();
        return 1;
    }

    for (;;)
    {
        // Server is running...
    }

    server.Stop();

    return 0;
}
