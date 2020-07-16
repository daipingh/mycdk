project(demo)
cmake_minimum_required(VERSION 2.8)

include(GNUInstallDirs)

list(APPEND CMAKE_MODULE_PATH
	${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/cmake)

link_directories(${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR})
include_directories(${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_INCLUDEDIR})


include(libmcl/libmcl)
set(mcl_libraries MCL::mcl_a)

if(WIN32)
	list(APPEND mcl_cflags /wd4100)
	list(APPEND mcl_defines _WIN32_WINNT=0x0600 _GNU_SOURCE _CRT_SECURE_NO_WARNINGS)
else()
	list(APPEND mcl_cflags -Wall -Wextra)
	list(APPEND mcl_cflags -Wno-unused-parameter -Wno-strict-aliasing)
	list(APPEND mcl_libraries pthread dl rt)
endif()

add_executable(demo main.cpp)
target_compile_definitions(demo PRIVATE ${mcl_defines})
target_compile_options(demo PRIVATE ${mcl_cflags})
target_include_directories(demo PRIVATE include)
target_link_libraries(demo ${mcl_libraries})

install(TARGETS demo
	RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
