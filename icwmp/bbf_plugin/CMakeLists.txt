cmake_minimum_required(VERSION 3.0)

PROJECT(libcwmpdm.so)

ADD_DEFINITIONS(-Wall -Werror -Wformat -g)
ADD_DEFINITIONS(-D_GNU_SOURCE)

# Compile and install libcwmpdm.so
ADD_LIBRARY(cwmpdm SHARED datamodel.c)
INSTALL(DIRECTORY DESTINATION etc/bbfdm/plugins)
INSTALL(TARGETS cwmpdm LIBRARY DESTINATION etc/bbfdm/plugins)

# Copy libcwmpdm.so to the main repo
add_custom_command(
    TARGET cwmpdm
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
            libcwmpdm.so
            ${CMAKE_SOURCE_DIR}
    COMMENT "Copying libcwmpdm.so to main repo"
)

# Add a custom target to trigger the custom command
add_custom_target(copy_lib_target
    DEPENDS cwmpdm
)

# Make sure the copy_lib_target is built after the library is built
add_dependencies(copy_lib_target cwmpdm)
