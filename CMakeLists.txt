project(lemuri-ssh-agent)

cmake_minimum_required(VERSION 2.6)
set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules;${CMAKE_MODULE_PATH}")

include(FindPkgConfig)

find_package(Qt5 COMPONENTS
    Core
    Network
)

set(CMAKE_AUTOMOC ON)

add_definitions("-DLOCALSTATEDIR=\"${LOCALSTATEDIR}\"" -std=c++11)

set(APP_VERSION "0.1.0")

configure_file(config.h.cmake
               ${CMAKE_CURRENT_BINARY_DIR}/config.h )

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR} ${CMAKE_MODULE_PATH})

include_directories(
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
)

add_subdirectory(ssh-agent)
