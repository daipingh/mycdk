project(libmcl C)
cmake_minimum_required(VERSION 2.8)

include(GNUInstallDirs)
option(MCL_CURL "Enable building mcl with curl support" ON)
option(MCL_OPENSSL "Enable building mcl with openssl support" ON)

link_directories(${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR})
include_directories(${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_INCLUDEDIR})


set(mcl_shared_libraries
	llhttp_a
	http_parser_a
	uv)

set(mcl_static_libraries
	llhttp_a
	http_parser_a
	uv_a)

set(mcl_sources
	src/http.c
	src/urlparser.c
	src/stream.c
	src/server.c
	src/utils.c
	src/applets.c
	src/filebuf.c
	src/fstail.c
	src/worker.c)

set(mcl_test_sources
	test/runner.c
	test/run-tests.c
	test/test-hello.c
	test/test-fail-always.c
	test/test-pass-always.c
	test/test-platform-output.c)

if(MCL_OPENSSL)
	find_package(OpenSSL REQUIRED)
	message(STATUS "Using OpenSSL ${OPENSSL_VERSION}")
	list(APPEND mcl_shared_libraries ${OPENSSL_LIBRARIES})
	list(APPEND mcl_static_libraries ${OPENSSL_LIBRARIES})
	include_directories(${OPENSSL_INCLUDE_DIR})
endif()

if(MCL_CURL)
	find_package(CURL COMPONENTS libcurl CONFIG)
	if(NOT CURL_FOUND)
		find_package(CURL REQUIRED)
		message(STATUS "Using CURL ${CURL_VERSION_STRING}")
	endif()

	if(WIN32)
		string(REGEX REPLACE "lib/libcurl(|-d)(|_imp)\\.lib" "lib/libcurl\\1_imp.lib" CURL_SHARED_LIBRARIES ${CURL_LIBRARIES})
		string(REGEX REPLACE "lib/libcurl(|-d)(|_imp)\\.lib" "lib/libcurl\\1.lib" CURL_STATIC_LIBRARIES ${CURL_LIBRARIES})
		string(REGEX REPLACE "bin/libcurl(|-d)\\.dll" "lib/libcurl\\1_imp.lib" CURL_SHARED_LIBRARIES ${CURL_SHARED_LIBRARIES})
		string(REGEX REPLACE "bin/libcurl(|-d)\\.dll" "lib/libcurl\\1.lib" CURL_STATIC_LIBRARIES ${CURL_STATIC_LIBRARIES})
	else()
		string(REGEX REPLACE "libcurl(|-d)\\.a" "libcurl\\1.so" CURL_SHARED_LIBRARIES ${CURL_LIBRARIES})
		string(REGEX REPLACE "libcurl(|-d)\\.so(\\.[0-9]+)*" "libcurl\\1.a" CURL_STATIC_LIBRARIES ${CURL_LIBRARIES})
	endif()
	
	get_target_property(CURL_LINK_LIBRARIES CURL::libcurl INTERFACE_LINK_LIBRARIES)
	list(APPEND mcl_shared_libraries ${CURL_SHARED_LIBRARIES} ${CURL_LINK_LIBRARIES})
	list(APPEND mcl_static_libraries ${CURL_STATIC_LIBRARIES} ${CURL_LINK_LIBRARIES})
	include_directories(${CURL_INCLUDE_DIR})
	list(APPEND mcl_sources src/curl.c)
endif()

if(WIN32)
	if(CMAKE_C_FLAGS)
		string(REGEX REPLACE "(/W[0-9] +| +/W[0-9]$)" "" CMAKE_C_FLAGS ${CMAKE_C_FLAGS})
	endif()
	if(CMAKE_CXX_FLAGS)
		string(REGEX REPLACE "(/W[0-9] +| +/W[0-9]$)" "" CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS})
	endif()
	list(APPEND mcl_cflags /W4 /wd4100)
	list(APPEND mcl_defines _WIN32_WINNT=0x0600 _GNU_SOURCE _CRT_SECURE_NO_WARNINGS)
	list(APPEND mcl_test_sources test/runner-win.c)
else()
	list(APPEND mcl_cflags -fPIC -fvisibility=hidden)
	list(APPEND mcl_cflags -Wall -Wextra)
	list(APPEND mcl_cflags -Wno-unused-parameter -Wno-strict-aliasing)
	list(APPEND mcl_test_sources test/runner-unix.c)
	list(APPEND mcl_shared_libraries pthread dl rt)
	list(APPEND mcl_static_libraries pthread dl rt)
endif()

add_library(mcl SHARED ${mcl_sources})
target_compile_definitions(mcl PRIVATE ${mcl_defines})
target_compile_options(mcl PRIVATE ${mcl_cflags})
target_include_directories(mcl PRIVATE include/mcl)
target_link_libraries(mcl ${mcl_libraries} ${mcl_shared_libraries})

add_library(mcl_a STATIC ${mcl_sources})
target_compile_definitions(mcl_a PRIVATE ${mcl_defines})
target_compile_options(mcl_a PRIVATE ${mcl_cflags})
target_include_directories(mcl_a PRIVATE include/mcl)
target_link_libraries(mcl_a ${mcl_libraries} ${mcl_static_libraries})

add_executable(mcl_run_tests ${mcl_test_sources})
target_compile_definitions(mcl_run_tests PRIVATE ${mcl_defines})
target_compile_options(mcl_run_tests PRIVATE ${mcl_cflags})
target_include_directories(mcl_run_tests PRIVATE include)
target_link_libraries(mcl_run_tests mcl ${mcl_shared_libraries})


# Install
foreach(x ${mcl_libraries})
    set(LIBS "${LIBS} -l${x}")
endforeach(x)
set(PACKAGE_VERSION "0.0.1")
set(includedir ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_INCLUDEDIR})
set(libdir ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR})
set(prefix ${CMAKE_INSTALL_PREFIX})
configure_file(libmcl.pc.cmakein ${CMAKE_CURRENT_BINARY_DIR}/libmcl.pc @ONLY)

if(NOT SKIP_INSTALL_LIBRARIES AND NOT SKIP_INSTALL_ALL)
    install(TARGETS mcl mcl_a EXPORT ${PROJECT_NAME}
            INCLUDES DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
            RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
            ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
            LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}")
    install(EXPORT ${PROJECT_NAME}
            DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/libmcl"
            NAMESPACE "MCL::")
endif()
if(NOT SKIP_INSTALL_HEADERS AND NOT SKIP_INSTALL_ALL)
    install(DIRECTORY include/ DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")
endif()
if(NOT SKIP_INSTALL_FILES AND NOT SKIP_INSTALL_ALL)
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libmcl.pc
            DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")
endif()


# Testing
add_test(NAME mcl_test
	COMMAND mcl_run_tests
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
