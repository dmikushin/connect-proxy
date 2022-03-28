cmake_minimum_required(VERSION 3.6)

project(proxy-connect)

add_executable(${PROJECT_NAME} connect.c)
target_compile_definitions(${PROJECT_NAME} PRIVATE SOCKLEN_T=socklen_t)

if (CMAKE_HOST_SOLARIS)
	target_link_libraries(${PROJECT_NAME} resolv socket nsl)
elseif (CMAKE_HOST_WIN32)
	if (MSVC)
		# On Win32 environment, platform SDK (for iphlpapi.lib) is required
		target_link_libraries(${PROJECT_NAME} advapi32 iphlpapi ws2_32)
	elseif (MINGW)
		target_link_libraries(${PROJECT_NAME} wsock32 iphlpapi)
	else()
		message(FATAL_ERROR "Unsupported Windows compiler")
	endif()
elseif (CMAKE_HOST_APPLE)
	#target_compile_definitions(${PROJECT_NAME} PRIVATE BIND_8_COMPAT=1)
	target_link_libraries(${PROJECT_NAME} resolv)
endif()

