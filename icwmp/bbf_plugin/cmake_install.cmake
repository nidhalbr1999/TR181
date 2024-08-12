# Install script for directory: /home/nidhal/Desktop/pfe/openwrt-23.05.3/build_dir/target-arm_cortex-a7+neon-vfpv4_musl_eabi/icwmp-9.6.7/bbf_plugin

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Release")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "1")
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "TRUE")
endif()

# Set default install directory permissions.
if(NOT DEFINED CMAKE_OBJDUMP)
  set(CMAKE_OBJDUMP "/home/nidhal/Desktop/pfe/openwrt-23.05.3/staging_dir/toolchain-arm_cortex-a7+neon-vfpv4_gcc-12.3.0_musl_eabi/bin/arm-openwrt-linux-muslgnueabi-objdump")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/etc/bbfdm/plugins" TYPE DIRECTORY FILES "")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/etc/bbfdm/plugins" TYPE SHARED_LIBRARY FILES "/home/nidhal/Desktop/pfe/openwrt-23.05.3/build_dir/target-arm_cortex-a7+neon-vfpv4_musl_eabi/icwmp-9.6.7/bbf_plugin/libcwmpdm.so")
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/etc/bbfdm/plugins/libcwmpdm.so" AND
     NOT IS_SYMLINK "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/etc/bbfdm/plugins/libcwmpdm.so")
    if(CMAKE_INSTALL_DO_STRIP)
      execute_process(COMMAND "/home/nidhal/Desktop/pfe/openwrt-23.05.3/build_dir/target-arm_cortex-a7+neon-vfpv4_musl_eabi/icwmp-9.6.7/:" "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/etc/bbfdm/plugins/libcwmpdm.so")
    endif()
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
endif()

