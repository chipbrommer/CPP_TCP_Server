# CMakeList.txt : CMake project for CPP_TCP_Server, include source and define
# project specific logic here.
#

# Add source to this project's executable.
add_executable (CPP_TCP_Server 
	"main.cpp"  
	"Source/tcp_server.h" 
	"Source/tcp_server.cpp")

# Linker for threading
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
target_link_libraries(CPP_TCP_Server PRIVATE Threads::Threads)

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET CPP_TCP_Server PROPERTY CXX_STANDARD 20)
endif()

# TODO: Add tests and install targets if needed.
