cmake_minimum_required(VERSION 3.10)


if (ENARX_RA)
    message("Compiling CCIPS client to be used with Enarx")
    add_compile_definitions(Enarx)
endif()


set(SRC_DIRECTORY "${PROJECT_SOURCE_DIR}/src")
# Include directories
include_directories("${SRC_DIRECTORY}")



if(ENARX_RA)
message(STATUS "Add libraries for enarx")
    add_library(i2nsf
    "${SRC_DIRECTORY}/sad_entry.c"
    "${SRC_DIRECTORY}/spd_entry.c"
    "${SRC_DIRECTORY}/utils.c" 
    "${SRC_DIRECTORY}/messages.c"
    "${SRC_DIRECTORY}/pfkeyv2_utils.c"
    "${SRC_DIRECTORY}/pfkeyv2_entry.c"
    "${SRC_DIRECTORY}/trust_client.c"
    "${SRC_DIRECTORY}/sysrepo_utils.c"
    "${SRC_DIRECTORY}/sysrepo_entries.c"
    "${SRC_DIRECTORY}/sysrepo_print.c"
    "${SRC_DIRECTORY}/log.c"
    "${SRC_DIRECTORY}/sad_entry.h"
    "${SRC_DIRECTORY}/spd_entry.h"
    "${SRC_DIRECTORY}/utils.h" 
    "${SRC_DIRECTORY}/messages.h"
    "${SRC_DIRECTORY}/pfkeyv2_utils.h"
    "${SRC_DIRECTORY}/pfkeyv2_entry.h"
    "${SRC_DIRECTORY}/trust_client.h"
    "${SRC_DIRECTORY}/sysrepo_utils.h"
    "${SRC_DIRECTORY}/sysrepo_entries.h"
    "${SRC_DIRECTORY}/sysrepo_print.h"
    "${SRC_DIRECTORY}/log.h"
    "${SRC_DIRECTORY}/trust_handler.h"
    "${SRC_DIRECTORY}/trust_handler.c"
    )
else()
message(STATUS "Add libraries for untrusted")
    add_library(i2nsf
    "${SRC_DIRECTORY}/sad_entry.c"
    "${SRC_DIRECTORY}/spd_entry.c"
    "${SRC_DIRECTORY}/utils.c" 
    "${SRC_DIRECTORY}/pfkeyv2_utils.c"
    "${SRC_DIRECTORY}/pfkeyv2_entry.c"
    "${SRC_DIRECTORY}/sysrepo_utils.c"
    "${SRC_DIRECTORY}/sysrepo_entries.c"
    "${SRC_DIRECTORY}/sysrepo_print.c"
    "${SRC_DIRECTORY}/log.c"
    "${SRC_DIRECTORY}/sad_entry.h"
    "${SRC_DIRECTORY}/spd_entry.h"
    "${SRC_DIRECTORY}/utils.h" 
    "${SRC_DIRECTORY}/pfkeyv2_utils.h"
    "${SRC_DIRECTORY}/pfkeyv2_entry.h"
    "${SRC_DIRECTORY}/sysrepo_utils.h"
    "${SRC_DIRECTORY}/sysrepo_entries.h"
    "${SRC_DIRECTORY}/sysrepo_print.h"
    "${SRC_DIRECTORY}/log.h")
endif()

# Add parson
if(ENARX_RA)
    add_library(parson STATIC "${PROJECT_SOURCE_DIR}/parson/parson.c")
    include_directories("${PROJECT_SOURCE_DIR}/parson")
    add_library(md5 STATIC "${PROJECT_SOURCE_DIR}/md5-c/md5.c")
    include_directories("${PROJECT_SOURCE_DIR}/md5-c")
endif()

include_directories("${SRC_DIRECTORY}")
# add the executable
add_executable(${PROJECT_NAME} 
    "${PROJECT_SOURCE_DIR}/cmd/i2nsf_ra/main.c"
    # "${PROJECT_SOURCE_DIR}/cmd/i2nsf_enarx/main_test.c"
    # "${PROJECT_SOURCE_DIR}/test_trusted.c"
    "${SRC_DIRECTORY}/constants.h"
    "${SRC_DIRECTORY}/host.h"
)


# Inlude sysrepo
include("${CMAKE_SOURCE_DIR}/build-scripts/ImportSysrepo.cmake")
# Link libraries
if(ENARX_RA)
message(STATUS "Linking libraries for enarx")
target_link_libraries(${PROJECT_NAME} PUBLIC 
    i2nsf
    parson
    md5
    ${SYSREPO_LIBRARIES}
    ${LIBYANG_LIBRARIES}
    pthread
)
else() 
message(STATUS "Linking libraries for untrusted target")
target_link_libraries(${PROJECT_NAME} PUBLIC 
    i2nsf
    ${SYSREPO_LIBRARIES}
    ${LIBYANG_LIBRARIES}
    pthread
)
endif()


# add the binary tree to the search path for include files
target_include_directories(${PROJECT_NAME} PUBLIC
    "${PROJECT_BINARY_DIR}"
)


set_target_properties(${PROJECT_NAME} PROPERTIES OUTPUT_NAME "i2nsf_cfgipsec2")
