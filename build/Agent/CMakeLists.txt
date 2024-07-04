cmake_minimum_required(VERSION 3.10)
set(CMAKE_BUILD_TYPE Debug)
set(TARGET ${TARGET} "rich_app")
message(STATUS "Selected target is ${TARGET}")
option(ENARX_RA "Add the depencies and compiles for the Enarx rich aplication" OFF)
option(ENARX_TA "Add the depencies and compile the libraries to be used by RUST for the Trusted Application" OFF)



if(ENARX_TA)
    message(STATUS "Selected Enarx TA option")
    # set(CMAKE_C_COMPILER "/home/debian/wasi-sdk/build/wasi-sdk-17.0/bin/clang")
    set(CMAKE_C_COMPILER "$ENV{WASI_CLANG}")
    set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -g -Wall -Wextra -fPIC -target wasm32-wasi")
    add_compile_definitions(Trusted)
    add_compile_definitions(Enarx)
elseif(ENARX_RA)
    message(STATUS "Selected Enarx RA option")
    set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/build-scripts/CMakeModules/")
    set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -g -Wall -Wextra -pthread")
    add_compile_definitions(Trusted)
    add_compile_definitions(Enarx)
else()
    message(STATUS "Selected Default option")
    set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/build-scripts/CMakeModules/")
    set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -g -Wall -Wextra -pthread")
endif()



# set the project name and version
set (PROJECT_NAME "i2nsf_cfgipsec")
project(${PROJECT_NAME} VERSION 1.0)

include(GNUInstallDirs)
include(CheckFunctionExists)
include(CheckIncludeFile)

if(ENARX_TA)
include("cmd/i2nsf_enarx/CMakeLists.txt")
else()
include("cmd/i2nsf_ra/CMakeLists.txt")
endif()
