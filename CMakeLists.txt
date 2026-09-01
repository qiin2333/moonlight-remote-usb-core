cmake_minimum_required(VERSION 3.20)
project(moonlight_remote_usb_core LANGUAGES C)

include(CTest)

find_program(CARGO_EXECUTABLE cargo REQUIRED)
option(RUSB_CORE_RELEASE "Build the Rust core in release mode" ON)

if(RUSB_CORE_RELEASE)
    set(RUSB_CARGO_PROFILE release)
    set(RUSB_CARGO_ARGS --release)
else()
    set(RUSB_CARGO_PROFILE debug)
    set(RUSB_CARGO_ARGS)
endif()

if(WIN32)
    set(RUSB_STATIC_LIBRARY
        "${CMAKE_CURRENT_SOURCE_DIR}/target/${RUSB_CARGO_PROFILE}/moonlight_remote_usb_core.lib")
else()
    set(RUSB_STATIC_LIBRARY
        "${CMAKE_CURRENT_SOURCE_DIR}/target/${RUSB_CARGO_PROFILE}/libmoonlight_remote_usb_core.a")
endif()

add_custom_command(
    OUTPUT "${RUSB_STATIC_LIBRARY}"
    COMMAND "${CARGO_EXECUTABLE}" build ${RUSB_CARGO_ARGS} --locked
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    DEPENDS
        Cargo.toml
        Cargo.lock
        src/lib.rs
        src/broker.rs
        src/error.rs
        src/executor.rs
        src/ffi.rs
        src/pdu.rs
        src/session.rs
        src/transport.rs
        src/usbip.rs
        src/wire.rs
    VERBATIM)

add_custom_target(moonlight_remote_usb_core_build ALL
                  DEPENDS "${RUSB_STATIC_LIBRARY}")

add_library(moonlight_remote_usb_core STATIC IMPORTED GLOBAL)
set_target_properties(moonlight_remote_usb_core PROPERTIES
    IMPORTED_LOCATION "${RUSB_STATIC_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/include")
add_dependencies(moonlight_remote_usb_core moonlight_remote_usb_core_build)

if(BUILD_TESTING)
    add_executable(remote_usb_ffi_smoke tests/ffi_c/ffi_smoke.c)
    target_link_libraries(remote_usb_ffi_smoke PRIVATE moonlight_remote_usb_core)
    if(UNIX AND NOT APPLE)
        target_link_libraries(remote_usb_ffi_smoke PRIVATE dl pthread m)
    endif()
    if(WIN32)
        target_link_libraries(remote_usb_ffi_smoke PRIVATE
                              advapi32 bcrypt ntdll userenv ws2_32)
    endif()
    add_test(NAME remote_usb_ffi_smoke COMMAND remote_usb_ffi_smoke)
endif()
