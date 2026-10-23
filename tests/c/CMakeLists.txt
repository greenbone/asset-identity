# SPDX-FileCopyrightText: 2026 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-only

cmake_minimum_required(VERSION 3.18)
project(gvm_asset_identity_tests C)
include(CTest)
find_package(PkgConfig REQUIRED)
pkg_check_modules(GLIB REQUIRED IMPORTED_TARGET glib-2.0)
find_package(cgreen 1.6.4 CONFIG QUIET)
if(cgreen_FOUND)
  find_library(CGREEN_LIBRARY NAMES cgreen HINTS "${cgreen_DIR}/../.." REQUIRED)
  set(CGREEN_LINK_TARGET "${CGREEN_LIBRARY}")
else()
  pkg_check_modules(CGREEN REQUIRED IMPORTED_TARGET cgreen>=1.6.4)
  set(CGREEN_LINK_TARGET PkgConfig::CGREEN)
endif()
set(
  IDENTITY_ROOT
  "${CMAKE_CURRENT_SOURCE_DIR}/../../dist"
  CACHE PATH
  "Installed library root"
)
set(IDENTITY_LIBDIR "${IDENTITY_ROOT}" CACHE PATH "Shared library directory")
set(
  IDENTITY_INCLUDEDIR
  "${IDENTITY_ROOT}/include"
  CACHE PATH
  "Public header directory"
)
find_library(
  IDENTITY_LIBRARY
  NAMES gvm_asset_identity
  PATHS "${IDENTITY_LIBDIR}"
  NO_DEFAULT_PATH
  REQUIRED
)
foreach(suite reconciliation policy memory)
  add_executable(test_${suite} test_${suite}.c)
  target_compile_features(test_${suite} PRIVATE c_std_11)
  target_compile_options(test_${suite} PRIVATE -Wall -Wextra -Werror -Wpedantic)
  target_include_directories(
    test_${suite}
    PRIVATE "${IDENTITY_INCLUDEDIR}" ${CGREEN_INCLUDE_DIRS}
  )
  target_link_libraries(
    test_${suite}
    PRIVATE "${IDENTITY_LIBRARY}" ${CGREEN_LINK_TARGET} PkgConfig::GLIB
  )
  set_target_properties(
    test_${suite}
    PROPERTIES BUILD_RPATH "${IDENTITY_LIBDIR}"
  )
  add_test(
    NAME ${suite}
    COMMAND
      "${CMAKE_COMMAND}" -E env --unset=LD_LIBRARY_PATH --unset=LD_PRELOAD
      "$<TARGET_FILE:test_${suite}>"
  )
  # Forking after Go runtime initialization would discard its worker threads.
  set_tests_properties(
    ${suite}
    PROPERTIES ENVIRONMENT "CGREEN_NO_FORK=1" TIMEOUT 60
  )
endforeach()

target_compile_definitions(
  test_reconciliation
  PRIVATE
    TLS_SCANNER_CERTIFICATE_PATH="${CMAKE_CURRENT_SOURCE_DIR}/../../identity/testdata/tls_scanner_certificate.txt"
)

set(
  IDENTITY_CONSUMER_SOURCE
  "${CMAKE_CURRENT_SOURCE_DIR}/consumer.c"
  CACHE FILEPATH
  "Standalone C consumer"
)
add_executable(test_consumer "${IDENTITY_CONSUMER_SOURCE}")
target_compile_features(test_consumer PRIVATE c_std_11)
target_compile_options(test_consumer PRIVATE -Wall -Wextra -Werror -Wpedantic)
target_include_directories(test_consumer PRIVATE "${IDENTITY_INCLUDEDIR}")
target_link_libraries(
  test_consumer
  PRIVATE "${IDENTITY_LIBRARY}" PkgConfig::GLIB
)
set_target_properties(test_consumer PROPERTIES BUILD_RPATH "${IDENTITY_LIBDIR}")
add_test(
  NAME consumer
  COMMAND
    "${CMAKE_COMMAND}" -E env --unset=LD_LIBRARY_PATH --unset=LD_PRELOAD
    "$<TARGET_FILE:test_consumer>"
)
set_tests_properties(consumer PROPERTIES TIMEOUT 30)
