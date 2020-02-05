cmake_minimum_required(VERSION 2.8)
project(MYCDK)

#include(CheckLibraryExists)
#include(CheckSymbolExists)
#include(CheckFunctionExists)
include(CheckIncludeFile)
include(CheckTypeSize)
include(GNUInstallDirs)
include(ExternalProject)

option(BUILD_PROJECT_LIBMCL "build project libmcl" OFF)
option(BUILD_PROJECT_LIBUV "build project libuv" OFF)
option(BUILD_PROJECT_LLHTTP "build project llhttp" OFF)
option(BUILD_PROJECT_HTTP_PARSER "build project http-parser" OFF)
option(BUILD_PROJECT_CURL "build project curl" OFF)
option(BUILD_PROJECT_ZLIB "build project curl" OFF)


# setup build infos.
get_cmake_property(CACHE_VARS CACHE_VARIABLES)
foreach(CACHE_VAR ${CACHE_VARS})
    if("__${CACHE_VAR}" MATCHES "^__BUILD_PROJECT_(.*)")
        set(BUILD_${CMAKE_MATCH_1} ${BUILD_PROJECT_${CMAKE_MATCH_1}})
    endif()
endforeach()

set(BUILD_LIBMCL ON)
# setup project dependencies.
if(BUILD_LIBMCL)
	set(BUILD_LIBUV ON)
	set(BUILD_LLHTTP ON)
	set(BUILD_HTTP_PARSER ON)
	set(BUILD_CURL ON)
endif()
if(BUILD_CURL)
    set(BUILD_ZLIB ON)
	set(BUILD_OPENSSL ON)
endif()


# build args variable based on cache variables.
unset(MYCDK_CMAKE_ARGS)
get_cmake_property(CACHE_VARS CACHE_VARIABLES)
foreach(CACHE_VAR ${CACHE_VARS})
    get_property(CACHE_VAR_HELPSTRING CACHE ${CACHE_VAR} PROPERTY HELPSTRING)
    if("__${CACHE_VAR}" STREQUAL "__CMAKE_BUILD_TYPE" OR
        "__${CACHE_VAR}" STREQUAL "__CMAKE_C_FLAGS" OR
        "__${CACHE_VAR}" STREQUAL "__CMAKE_CXX_FLAGS" OR
        "__${CACHE_VAR}" STREQUAL "__CMAKE_TOOLCHAIN_FILE" OR
        CACHE_VAR_HELPSTRING STREQUAL "No help, variable specified on the command line.")
        get_property(CACHE_VAR_TYPE CACHE ${CACHE_VAR} PROPERTY TYPE)
        if(CACHE_VAR_TYPE STREQUAL "UNINITIALIZED")
            set(CACHE_VAR_TYPE)
        else()
            set(CACHE_VAR_TYPE :${CACHE_VAR_TYPE})
        endif()
        list(APPEND MYCDK_CMAKE_ARGS "-D${CACHE_VAR}${CACHE_VAR_TYPE}=${${CACHE_VAR}}")
    endif()
endforeach()
set(MYCDK_INSTALL_PREFIX ${CMAKE_CURRENT_BINARY_DIR}/output)
set(MYCDK_PROJECT_TOUCH_SCRIPT ${CMAKE_CURRENT_SOURCE_DIR}/CMake/ProjectTouchScript.cmake)
list(APPEND MYCDK_CMAKE_ARGS "-DCMAKE_INSTALL_PREFIX:PATH=${MYCDK_INSTALL_PREFIX}")


# output directories.
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${MYCDK_INSTALL_PREFIX}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${MYCDK_INSTALL_PREFIX}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${MYCDK_INSTALL_PREFIX}/bin)
link_directories(${CMAKE_ARCHIVE_OUTPUT_DIRECTORY})
link_directories(${CMAKE_LIBRARY_OUTPUT_DIRECTORY})
link_directories(${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
link_directories(${MYCDK_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR})
include_directories(${MYCDK_INSTALL_PREFIX}/${CMAKE_INSTALL_INCLUDEDIR})


# add project libuv.
if(BUILD_LIBUV)
	ExternalProject_Add(libuv
		PREFIX third/libuv-v1.33.1
		URL ${CMAKE_SOURCE_DIR}/third/libuv-v1.33.1.tar.gz
		#URL https://github.com/libuv/libuv/archive/v1.33.1.tar.gz
		URL_MD5 69353161348B493293A47CFB3832BA30
		BUILD_IN_SOURCE 0
		BUILD_ALWAYS 0
		INSTALL_DIR ${MYCDK_INSTALL_PREFIX}
		BUILD_BYPRODUCTS uv uv_a
		CMAKE_ARGS "${MYCDK_CMAKE_ARGS};-DBUILD_TESTING:BOOL=OFF")

	add_custom_target(libuv_copy
		COMMAND ${CMAKE_COMMAND} -E copy_if_different ${MYCDK_INSTALL_PREFIX}/lib/$<CONFIG>/uv_a.lib ${MYCDK_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/uv_a.lib
		COMMAND ${CMAKE_COMMAND} -E copy_if_different ${MYCDK_INSTALL_PREFIX}/lib/$<CONFIG>/uv.lib ${MYCDK_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/uv.lib
		COMMAND ${CMAKE_COMMAND} -E copy_if_different ${MYCDK_INSTALL_PREFIX}/lib/$<CONFIG>/uv.dll ${MYCDK_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR}/uv.dll)
	add_dependencies(libuv_copy libuv)
endif()

# add project llhttp.
if(BUILD_LLHTTP)
	ExternalProject_Add(llhttp
		PREFIX third/llhttp-release-v2.0.1
		URL ${CMAKE_SOURCE_DIR}/third/llhttp-release-v2.0.1.tar.gz
		#URL https://codeload.github.com/nodejs/llhttp/tar.gz/release/v2.0.1
		URL_MD5 878CE7E7D802D3074A533F79D9BCFB18
		PATCH_COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/CMake/llhttp-release.CMakeLists.txt CMakeLists.txt
		BUILD_IN_SOURCE 0
		BUILD_ALWAYS 0
		INSTALL_DIR ${MYCDK_INSTALL_PREFIX}
		BUILD_BYPRODUCTS llhttp llhttp_a
		CMAKE_ARGS "${MYCDK_CMAKE_ARGS}")
endif()

# add project http-parser.
if(BUILD_HTTP_PARSER)
	if(ON)
		ExternalProject_Add(http-parser
			PREFIX third/http-parser-2.9.2
			URL ${CMAKE_SOURCE_DIR}/third/http-parser-2.9.2.tar.gz
			URL_MD5 AAF0421392E1C0D1F2D51EC9F0E08CC1
			PATCH_COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/CMake/http-parser.CMakeLists.txt CMakeLists.txt
			BUILD_IN_SOURCE 0
			BUILD_ALWAYS 0
			INSTALL_DIR ${MYCDK_INSTALL_PREFIX}
			BUILD_BYPRODUCTS http_parser http_parser_a
			CMAKE_ARGS "${MYCDK_CMAKE_ARGS};-DHTTPPARSER_BUILD_TESTS:BOOL=OFF")
	else()
		string(TOUPPER ${CMAKE_BUILD_TYPE} CMAKE_BUILD_TYPE_UPPER)
		list(APPEND HTTP_PARSER_BUILD_ARGS
			CC=${CMAKE_C_COMPILER}
			PREFIX=${MYCDK_INSTALL_PREFIX})
		list(APPEND HTTP_PARSER_ENV_EXPORT
			export "CFLAGS=${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE_UPPER}}" &&
			export "CPPFLAGS=${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_${CMAKE_BUILD_TYPE_UPPER}}" &&
			export "LDFLAGS=")
		ExternalProject_Add(http-parser
			PREFIX third/http-parser-2.9.2
			URL ${CMAKE_SOURCE_DIR}/third/http-parser-2.9.2.tar.gz
			URL_MD5 AAF0421392E1C0D1F2D51EC9F0E08CC1
			UPDATE_COMMAND echo nothing to update
			#CONFIGURE_COMMAND echo nothing to configure
			CONFIGURE_COMMAND ${HTTP_PARSER_ENV_EXPORT} && ${CMAKE_MAKE_PROGRAM} clean ${HTTP_PARSER_BUILD_ARGS}
			BUILD_COMMAND ${HTTP_PARSER_ENV_EXPORT} && ${CMAKE_MAKE_PROGRAM} ${HTTP_PARSER_BUILD_ARGS}
			BUILD_IN_SOURCE 1
			BUILD_ALWAYS 0
			INSTALL_COMMAND ${HTTP_PARSER_ENV_EXPORT} && ${CMAKE_MAKE_PROGRAM} install ${HTTP_PARSER_BUILD_ARGS}
			INSTALL_DIR ${MYCDK_INSTALL_PREFIX})
	endif()
endif()

# add project zlib.
if(BUILD_ZLIB)
	find_package(ZLIB)
	if(ZLIB_FOUND)
		message(STATUS "Using ZLIB ${ZLIB_VERSION_STRING}")
		include_directories(${ZLIB_INCLUDE_DIRS})
	else()
		ExternalProject_Add(zlib
			PREFIX third/zlib-1.2.11
			URL ${CMAKE_SOURCE_DIR}/third/zlib-1.2.11.tar.xz
			BUILD_IN_SOURCE 0
			BUILD_ALWAYS 0
			INSTALL_DIR ${MYCDK_INSTALL_PREFIX}
			BUILD_BYPRODUCTS zlib
			CMAKE_ARGS "${MYCDK_CMAKE_ARGS}")
	endif()
endif()

# add project openssl.
if(BUILD_OPENSSL)
	find_package(OpenSSL)
	if(OpenSSL_FOUND)
		message(STATUS "Using OpenSSL ${OpenSSL_VERSION_STRING}")
		include_directories(${OpenSSL_INCLUDE_DIRS})
	else()
		if(WIN32)
			if(${CMAKE_BUILD_TYPE} STREQUAL "Debug")
				set(OPENSSL_BUILD_TYPE "debug-")
			else()
				set(OPENSSL_BUILD_TYPE "")
			endif()
			if(CMAKE_CL_64)
				set(OPENSSL_BUILD_TYPE "${OPENSSL_BUILD_TYPE}VC-WIN64A")
				set(OPENSSL_CONFIGURE_BAT "ms\\do_win64a.bat")
			else()
				set(OPENSSL_BUILD_TYPE "${OPENSSL_BUILD_TYPE}VC-WIN32")
				set(OPENSSL_CONFIGURE_BAT "ms\\do_ms.bat")
			endif()
			list(APPEND OPENSSL_CONFIGURE_ARGS "${OPENSSL_BUILD_TYPE}")
			list(APPEND OPENSSL_CONFIGURE_ARGS "--prefix=${MYCDK_INSTALL_PREFIX}")
			ExternalProject_Add(OpenSSL
				PREFIX third/openssl-OpenSSL_1_0_2u
				URL ${CMAKE_SOURCE_DIR}/third/openssl-OpenSSL_1_0_2u.tar.gz
				URL_MD5 C38577624507DAD3A4A1F3D07B84FA59
				UPDATE_COMMAND echo nothing to update
				CONFIGURE_COMMAND perl ./Configure ${OPENSSL_CONFIGURE_ARGS} && ${OPENSSL_CONFIGURE_BAT}
				BUILD_COMMAND nmake -f ms\\ntdll.mak
				BUILD_IN_SOURCE 1
				BUILD_ALWAYS 0
				INSTALL_COMMAND nmake -f ms\\ntdll.mak install
				INSTALL_DIR ${MYCDK_INSTALL_PREFIX})
		endif()
	endif()
endif()

# add project curl.
if(BUILD_CURL)
	list(APPEND CURL_CMAKE_ARGS "-DBUILD_CURL_EXE:BOOL=OFF")
	#list(APPEND CURL_CMAKE_ARGS "-DCURL_DISABLE_FTP:BOOL=ON")
	list(APPEND CURL_CMAKE_ARGS "-DCURL_DISABLE_LDAP:BOOL=ON")
	list(APPEND CURL_CMAKE_ARGS "-DCURL_DISABLE_LDAPS:BOOL=ON")
	list(APPEND CURL_CMAKE_ARGS "-DCURL_DISABLE_TELNET:BOOL=ON")
	list(APPEND CURL_CMAKE_ARGS "-DCURL_DISABLE_DICT:BOOL=ON")
	list(APPEND CURL_CMAKE_ARGS "-DCURL_DISABLE_FILE:BOOL=ON")
	list(APPEND CURL_CMAKE_ARGS "-DCURL_DISABLE_TFTP:BOOL=ON")
	list(APPEND CURL_CMAKE_ARGS "-DCURL_DISABLE_HTTP:BOOL=OFF")
	list(APPEND CURL_CMAKE_ARGS "-DCURL_DISABLE_RTSP:BOOL=ON")
	list(APPEND CURL_CMAKE_ARGS "-DCURL_DISABLE_POP3:BOOL=ON")
	list(APPEND CURL_CMAKE_ARGS "-DCURL_DISABLE_IMAP:BOOL=ON")
	list(APPEND CURL_CMAKE_ARGS "-DCURL_DISABLE_SMTP:BOOL=OFF")
	list(APPEND CURL_CMAKE_ARGS "-DCURL_DISABLE_GOPHER:BOOL=ON")
	list(APPEND CURL_CMAKE_ARGS "-DBUILD_TESTING:BOOL=OFF")
	if(WIN32)
		list(APPEND CURL_CMAKE_ARGS "-DCMAKE_USE_OPENSSL:BOOL=ON")
		#list(APPEND CURL_CMAKE_ARGS "-DOPENSSL_ROOT_DIR:PATH=/usr/local/ssl")
	endif()
	list(APPEND CURL_CMAKE_ARGS "-DZLIB_ROOT:PATH=${MYCDK_INSTALL_PREFIX}")
	ExternalProject_Add(curl
		PREFIX third/curl-7.61.0
		URL ${CMAKE_SOURCE_DIR}/third/curl-7.61.0.tar.gz
		BUILD_IN_SOURCE 0
		BUILD_ALWAYS 0
		INSTALL_DIR ${MYCDK_INSTALL_PREFIX}
		BUILD_BYPRODUCTS libcurl
		CMAKE_ARGS "${MYCDK_CMAKE_ARGS};${CURL_CMAKE_ARGS};-DCURL_STATICLIB:BOOL=OFF")
	ExternalProject_Add(curl-static
		PREFIX third/curl-7.61.0
		URL ${CMAKE_SOURCE_DIR}/third/curl-7.61.0.tar.gz
		BUILD_IN_SOURCE 0
		BUILD_ALWAYS 0
		INSTALL_DIR ${MYCDK_INSTALL_PREFIX}
		BUILD_BYPRODUCTS libcurl
		CMAKE_ARGS "${MYCDK_CMAKE_ARGS};${CURL_CMAKE_ARGS};-DCURL_STATICLIB:BOOL=ON")
	#if(TARGET zlib)
	#	add_dependencies(curl zlib)
	#	add_dependencies(curl-static zlib)
	#endif()
	#if(TARGET OpenSSL)
	#	add_dependencies(curl OpenSSL)
	#	add_dependencies(curl-static OpenSSL)
	#endif()
endif()

# add project libmcl.
if(BUILD_LIBMCL)
	list(APPEND MCL_CMAKE_ARGS "-DMCL_CURL:BOOL=ON")
	ExternalProject_Add(libmcl
		PREFIX libmcl
		SOURCE_DIR ${CMAKE_SOURCE_DIR}/libmcl
		BUILD_IN_SOURCE 0
		BUILD_ALWAYS 0
		INSTALL_DIR ${MYCDK_INSTALL_PREFIX}
		BUILD_BYPRODUCTS mcl mcl_a
		CMAKE_ARGS "${MYCDK_CMAKE_ARGS};${MCL_CMAKE_ARGS}")
	add_dependencies(libmcl libuv libuv_copy http-parser llhttp curl curl-static)
endif()

add_subdirectory(demo)
