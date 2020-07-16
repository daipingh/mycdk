
# Load cmake parameters used to compile third-party projects.
macro(LoadCMakeArgs ret_variable)
	unset(__CMAKE_ARGS)
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
			list(APPEND __CMAKE_ARGS "-D${CACHE_VAR}${CACHE_VAR_TYPE}=${${CACHE_VAR}}")
		endif()
	endforeach()
	
	set(${ret_variable} ${__CMAKE_ARGS})
endmacro()
