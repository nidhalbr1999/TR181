cmake_minimum_required(VERSION 3.0)

PROJECT(icwmpd)

ADD_DEFINITIONS(-Wall -Werror -Wformat -g)
ADD_DEFINITIONS(-D_GNU_SOURCE)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -I${PROJECT_SOURCE_DIR}")

FILE(GLOB ICWMP_SOURCES *.c)

# Compile and install icwmpd
ADD_EXECUTABLE(icwmpd ${ICWMP_SOURCES})
TARGET_LINK_LIBRARIES(icwmpd pthread z m json-c uci ubox ubus blobmsg_json curl mxml uuid ssl crypto)
INSTALL(FILES icwmpd PERMISSIONS OWNER_EXECUTE DESTINATION usr/sbin)
INSTALL(DIRECTORY DESTINATION etc/icwmpd)
INSTALL(DIRECTORY DESTINATION var/run/icwmpd)

# Copy icwmpd to the main repo
add_custom_command(
    TARGET icwmpd POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
            icwmpd
            ${CMAKE_SOURCE_DIR}
)

# Add a custom target to trigger the custom command
add_custom_target(copy_daemon_target
    DEPENDS icwmpd
)

# Make sure the copy_daemon_target is built after the library is built
add_dependencies(copy_daemon_target icwmpd)
