# Pkg: ApacheForCPanel
# Trg: mod_lsapi
# Default HTTPD_USER: "apache"
# Default UID_MIN: 100
# Default GID_MIN: 100
# Default USERDIR_SUFFIX: "public_html"
# Default DOC_ROOT: "/"
# Default SAFE_PATH: "/usr/local/bin:/usr/bin:/bin"
# Default ALLOWED_CMD: "lsphp"
# Default ALLOWED_DIR: "/usr/local/bin"
# Default SAFE_DIR: "/opt/alt"
# Default without WITH_CRIU

CMAKE_MINIMUM_REQUIRED(VERSION 2.4)

PROJECT(MOD_LSAPI)

# ------------------------------------
# Set variables for sulsphp

IF(NOT DEFINED HTTPD_USER)
SET (HTTPD_USER "apache")
ENDIF(NOT DEFINED HTTPD_USER) 

IF(NOT DEFINED UID_MIN)
SET (UID_MIN "100")
ENDIF(NOT DEFINED UID_MIN) 

IF(NOT DEFINED GID_MIN)
SET (GID_MIN "100")
ENDIF(NOT DEFINED GID_MIN) 

IF(NOT DEFINED USERDIR_SUFFIX)
SET (USERDIR_SUFFIX "public_html")
ENDIF(NOT DEFINED USERDIR_SUFFIX) 

IF(NOT DEFINED DOC_ROOT)
SET (DOC_ROOT "/")
ENDIF(NOT DEFINED DOC_ROOT) 

IF(NOT DEFINED SAFE_PATH)
SET (SAFE_PATH "/usr/local/bin:/usr/bin:/bin")
ENDIF(NOT DEFINED SAFE_PATH) 

IF(NOT DEFINED ALLOWED_CMD)
SET (ALLOWED_CMD "lsphp")
ENDIF(NOT DEFINED ALLOWED_CMD) 

IF(NOT DEFINED ALLOWED_DIR)
SET (ALLOWED_DIR "/usr/local/bin")
ENDIF(NOT DEFINED ALLOWED_DIR) 

IF(NOT DEFINED SAFE_DIR)
SET (SAFE_DIR "/opt/alt")
ENDIF(NOT DEFINED SAFE_DIR) 

SET (SULSPHP_HTTPD_USER "\\\"${HTTPD_USER}\\\"")
SET (SULSPHP_UID_MIN "${UID_MIN}")
SET (SULSPHP_GID_MIN "${GID_MIN}")
SET (SULSPHP_USERDIR_SUFFIX "\\\"${USERDIR_SUFFIX}\\\"")
SET (SULSPHP_DOC_ROOT "\\\"${DOC_ROOT}\\\"")
SET (SULSPHP_SAFE_PATH "\\\"${SAFE_PATH}\\\"")
SET (SULSPHP_ALLOWED_CMD "\\\"${ALLOWED_CMD}\\\"")
SET (SULSPHP_ALLOWED_DIR "\\\"${ALLOWED_DIR}\\\"")
SET (SULSPHP_SAFE_DIR "\\\"${SAFE_DIR}\\\"")

# This code eliminates error message of cmake...
if(COMMAND cmake_policy)
     cmake_policy(SET CMP0003 NEW)
#     cmake_policy(SET CMP0002 NEW)
endif(COMMAND cmake_policy)

SET(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

# ------ Define needed paths

SET(SRC "${CMAKE_SOURCE_DIR}/src")
SET(LIBUTILSRC "${SRC}/liblscapi-util")
SET(INCPATH "${SRC}/include")
SET(EXECUTABLE_OUTPUT_PATH "${CMAKE_SOURCE_DIR}/build/bin")
SET(LIBRARY_OUTPUT_PATH "${CMAKE_SOURCE_DIR}/build/lib")


# ------ Let's find Apache

### For DirectAdmin build only #########################################################################################################

# Search for Apache and determine version and paths
FIND_PACKAGE(ApacheForCPanel REQUIRED)

IF (APACHE_2_4)

SET (FINAL_APACHE_DEFINE APACHE2_4)
MESSAGE (STATUS "****** DirectAdmin Apache 2.4 found")


ELSEIF (APACHE_2_2)

SET (FINAL_APACHE_DEFINE APACHE2_2)
MESSAGE (STATUS "****** DirectAdmin Apache 2.2 found")


ELSE (APACHE_2_4)
MESSAGE( FATAL_ERROR "Apache version should be 2.4 or 2.2")
ENDIF (APACHE_2_4)

MESSAGE (STATUS "****** DirectAdmin Apache HTTPD Include dir:   ${HTTPD_INCLUDE_DIR}")
MESSAGE (STATUS "****** DirectAdmin Apache APR Include dir:     ${APR_INCLUDE_DIR}")
MESSAGE (STATUS "****** DirectAdmin Apache APRUTIL Include dir: ${APRUTIL_INCLUDE_DIR}")
MESSAGE (STATUS "****** DirectAdmin Apache HTTPD Modules dir:   ${HTTPD_MODULES}")
MESSAGE (STATUS "****** DirectAdmin Apache HTTPD Libraries dir: ${APACHE_LIB_DIR}")
MESSAGE (STATUS "****** DirectAdmin Apache HTTPD Bin dir:       ${HTTPD_BIN}")


SET (FINAL_HTTPD_INCLUDE_DIR ${HTTPD_INCLUDE_DIR})
SET (FINAL_APR_INCLUDE_DIR ${APR_INCLUDE_DIR})
SET (FINAL_APRUTIL_INCLUDE_DIR ${APRUTIL_INCLUDE_DIR})
SET (FINAL_HTTPD_MODULES ${HTTPD_MODULES})
SET (FINAL_LIB_DIR ${APACHE_LIB_DIR})
SET (FINAL_HTTPD_BIN ${HTTPD_BIN})

###########################################################3

# ------ Define sets of compile flags

SET(HTTPD_COMPILE_FLAGS
   "-I${FINAL_HTTPD_INCLUDE_DIR} -I${FINAL_APR_INCLUDE_DIR} -I${FINAL_APRUTIL_INCLUDE_DIR} -D${FINAL_APACHE_DEFINE}"
)

SET(SULSPHP_COMPILE_FLAGS
   "-DSULSPHP_HTTPD_USER=${SULSPHP_HTTPD_USER} -DSULSPHP_UID_MIN=${SULSPHP_UID_MIN} -DSULSPHP_GID_MIN=${SULSPHP_GID_MIN} -DSULSPHP_DOC_ROOT=${SULSPHP_DOC_ROOT} -DSULSPHP_SAFE_PATH=${SULSPHP_SAFE_PATH} -DSULSPHP_ALLOWED_CMD=${SULSPHP_ALLOWED_CMD} -DSULSPHP_ALLOWED_DIR=${SULSPHP_ALLOWED_DIR} -DSULSPHP_SAFE_DIR=${SULSPHP_SAFE_DIR}"
)

SET(GCC_COMPILE_FLAGS
   "-std=gnu99 -DLINUX=2 -D_REENTRANT -D_GNU_SOURCE -Wall -g -O2 -pthread"
)

IF (DEFINED WITH_CRIU AND WITH_CRIU)

SET(COMMON_COMPILE_FLAGS
   "-DWITH_CRIU ${GCC_COMPILE_FLAGS}"
)

ELSE (DEFINED WITH_CRIU AND WITH_CRIU)

SET(COMMON_COMPILE_FLAGS
   "${GCC_COMPILE_FLAGS}"
)

ENDIF (DEFINED WITH_CRIU AND WITH_CRIU)

# ------ Define sets of sources with their properties

SET(libutil_SRCS
	${LIBUTILSRC}/config.c
	${LIBUTILSRC}/connect.c
	${LIBUTILSRC}/do.c
	${LIBUTILSRC}/parsevars.c
	${LIBUTILSRC}/httpreq.c
	${LIBUTILSRC}/mutex.c
	${LIBUTILSRC}/pool.c
	${LIBUTILSRC}/starter.c
	${LIBUTILSRC}/sulsphp.c
)
SET_SOURCE_FILES_PROPERTIES(${libutil_SRCS}
    PROPERTIES COMPILE_FLAGS "${HTTPD_COMPILE_FLAGS} ${SULSPHP_COMPILE_FLAGS} ${COMMON_COMPILE_FLAGS}"
    OBJECT_DEPENDS src/include/lscapi_config.h
    )

SET(mod_lsapi_SRCS ${SRC}/mod_lsapi/mod_lsapi.c)
SET_SOURCE_FILES_PROPERTIES(${mod_lsapi_SRCS}
    PROPERTIES COMPILE_FLAGS "${HTTPD_COMPILE_FLAGS} ${SULSPHP_COMPILE_FLAGS} ${COMMON_COMPILE_FLAGS}"
    OBJECT_DEPENDS src/include/lscapi_config.h
    )

# ------ Set some common things

SET(PACKAGE_VERSION "1.0")

INCLUDE_DIRECTORIES(${INCPATH})

# ------ Describe build targets with their properties

ADD_LIBRARY(mod_lsapi MODULE ${mod_lsapi_SRCS} ${libutil_SRCS})
SET_TARGET_PROPERTIES(mod_lsapi PROPERTIES PREFIX "")
TARGET_LINK_LIBRARIES(mod_lsapi lscapi)
INSTALL(TARGETS mod_lsapi LIBRARY
        DESTINATION ${FINAL_HTTPD_MODULES}
        COMPONENT Runtime
        )
