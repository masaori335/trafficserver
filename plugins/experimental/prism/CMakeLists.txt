#######################
#
#  Licensed to the Apache Software Foundation (ASF) under one or more contributor license
#  agreements.  See the NOTICE file distributed with this work for additional information regarding
#  copyright ownership.  The ASF licenses this file to you under the Apache License, Version 2.0
#  (the "License"); you may not use this file except in compliance with the License.  You may obtain
#  a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
#  or implied. See the License for the specific language governing permissions and limitations under
#  the License.
#
#######################

project(prism)

# No TSAPI or Cripts here, so the unit tests run it without a traffic_server.
add_library(prism_ir STATIC src/ir.cc src/ir_reader.cc src/registry.cc src/bind.cc src/txn_memory.cc)
set_target_properties(prism_ir PROPERTIES POSITION_INDEPENDENT_CODE TRUE)
target_include_directories(prism_ir PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(prism_ir PUBLIC ts::tsutil)

# Dynamic loading stays out of prism_ir, so its tests need no .so files.
add_library(prism_ext_loader STATIC src/ext_loader.cc)
set_target_properties(prism_ext_loader PROPERTIES POSITION_INDEPENDENT_CODE TRUE)
target_link_libraries(prism_ext_loader PUBLIC prism_ir ${CMAKE_DL_LIBS})

# An instance's YAML settings, read without a traffic_server so the unit tests run them.
add_library(prism_config STATIC src/config.cc)
set_target_properties(prism_config PROPERTIES POSITION_INDEPENDENT_CODE TRUE)
target_link_libraries(
  prism_config
  PUBLIC prism_ir
  PRIVATE yaml-cpp::yaml-cpp
)

# Reads a .so's manifest section from the file, so it builds and runs without a traffic_server.
add_library(prism_manifest STATIC src/manifest.cc)
target_include_directories(prism_manifest PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_SOURCE_DIR}/include)

# Installed so an extension can be built outside this tree.
install(FILES include/hrw4u/extension.h include/hrw4u/extension.hpp DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/hrw4u)

add_executable(hrw4u-extern tools/hrw4u-extern.cc)
target_link_libraries(hrw4u-extern PRIVATE prism_manifest)
install(TARGETS hrw4u-extern DESTINATION ${CMAKE_INSTALL_BINDIR})

# The example extension needs only the ABI headers: no TSAPI, no Cripts.
add_library(prism_ext_example_ua MODULE extensions/example_ua/example_ua.cc)
target_include_directories(prism_ext_example_ua PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
set_target_properties(prism_ext_example_ua PROPERTIES PREFIX "" SUFFIX ".so")
install(TARGETS prism_ext_example_ua DESTINATION ${CMAKE_INSTALL_LIBEXECDIR})

# prism.cc is a cript, so the plugin exists only where Cripts is built.
if(ENABLE_CRIPTS)
  add_atsplugin(prism src/prism.cc src/interp.cc src/cripts_bindings.cc src/cripts_bridge.cc src/cripts_bridge_addr.cc)
  target_link_libraries(prism PRIVATE prism_ext_loader prism_config ts::cripts)
  verify_remap_plugin(prism)
else()
  message(STATUS "prism: skipping prism.so - ENABLE_CRIPTS is OFF")
endif()

if(BUILD_TESTING)
  add_executable(test_prism_ir_reader unit_tests/test_ir_reader.cc)
  target_link_libraries(test_prism_ir_reader PRIVATE prism_ir Catch2::Catch2WithMain)
  add_catch2_test(NAME test_prism_ir_reader COMMAND test_prism_ir_reader)

  add_executable(test_prism_config unit_tests/test_config.cc)
  target_link_libraries(test_prism_config PRIVATE prism_config Catch2::Catch2WithMain)
  add_catch2_test(NAME test_prism_config COMMAND test_prism_config)

  add_executable(test_prism_txn_memory unit_tests/test_txn_memory.cc)
  target_link_libraries(test_prism_txn_memory PRIVATE prism_ir Catch2::Catch2WithMain)
  add_catch2_test(NAME test_prism_txn_memory COMMAND test_prism_txn_memory)

  add_executable(test_prism_binding unit_tests/test_binding.cc)
  target_link_libraries(test_prism_binding PRIVATE prism_ir Catch2::Catch2WithMain)
  add_catch2_test(NAME test_prism_binding COMMAND test_prism_binding)

  add_library(test_prism_wrong_abi_ext MODULE unit_tests/bad_ext.cc)
  target_include_directories(test_prism_wrong_abi_ext PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
  target_compile_definitions(test_prism_wrong_abi_ext PRIVATE BAD_EXT_WRONG_ABI)
  add_library(test_prism_no_init_ext MODULE unit_tests/bad_ext.cc)
  target_include_directories(test_prism_no_init_ext PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
  target_compile_definitions(test_prism_no_init_ext PRIVATE BAD_EXT_NO_INIT)

  add_executable(test_prism_ext_loader unit_tests/test_ext_loader.cc)
  target_link_libraries(test_prism_ext_loader PRIVATE prism_ext_loader Catch2::Catch2WithMain)
  target_compile_definitions(
    test_prism_ext_loader
    PRIVATE EXAMPLE_UA_SO="$<TARGET_FILE:prism_ext_example_ua>" WRONG_ABI_SO="$<TARGET_FILE:test_prism_wrong_abi_ext>"
            NO_INIT_SO="$<TARGET_FILE:test_prism_no_init_ext>"
  )
  add_dependencies(test_prism_ext_loader prism_ext_example_ua test_prism_wrong_abi_ext test_prism_no_init_ext)
  add_catch2_test(NAME test_prism_ext_loader COMMAND test_prism_ext_loader)

  add_executable(test_prism_manifest unit_tests/test_manifest.cc)
  target_link_libraries(test_prism_manifest PRIVATE prism_manifest Catch2::Catch2WithMain)
  target_compile_definitions(test_prism_manifest PRIVATE EXAMPLE_UA_SO="$<TARGET_FILE:prism_ext_example_ua>")
  add_dependencies(test_prism_manifest prism_ext_example_ua)
  if(ENABLE_CRIPTS)
    target_compile_definitions(test_prism_manifest PRIVATE PRISM_SO="$<TARGET_FILE:prism>")
    add_dependencies(test_prism_manifest prism)
  endif()
  add_catch2_test(NAME test_prism_manifest COMMAND test_prism_manifest)

  add_test(NAME test_prism_extern COMMAND hrw4u-extern $<TARGET_FILE:prism_ext_example_ua>)
  set_tests_properties(
    test_prism_extern PROPERTIES PASS_REGULAR_EXPRESSION "extern Example::UA::IsBot\\(string\\) -> bool pure;"
  )

  if(ENABLE_CRIPTS)
    # As src/cripts/unit_tests: the cases are a module that resolves the TS API against an executable carrying the core.
    add_library(
      test_prism_cripts_bridge_cases MODULE
      unit_tests/test_interp.cc unit_tests/test_bind_interp.cc unit_tests/test_cripts_bridge.cc
      unit_tests/test_addresses.cc src/interp.cc src/cripts_bridge.cc
    )
    target_include_directories(test_prism_cripts_bridge_cases PRIVATE ${CMAKE_SOURCE_DIR}/src/cripts/unit_tests)
    # Through prism_ir, the module has its own tsutil globals, such as the DbgCtl registry, as prism.so has.
    target_link_libraries(test_prism_cripts_bridge_cases PRIVATE prism_ir Catch2::Catch2 ts::cripts)
    set_target_properties(
      test_prism_cripts_bridge_cases
      PROPERTIES PREFIX ""
                 SUFFIX ".so"
                 LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )
    if(APPLE)
      target_link_options(test_prism_cripts_bridge_cases PRIVATE -undefined dynamic_lookup)
    endif()

    add_executable(test_prism_cripts_bridge unit_tests/cripts_bridge_main.cc)
    add_dependencies(test_prism_cripts_bridge test_prism_cripts_bridge_cases)
    target_compile_definitions(
      test_prism_cripts_bridge PRIVATE PRISM_TEST_CASES_PATH="$<TARGET_FILE:test_prism_cripts_bridge_cases>"
    )
    set_target_properties(test_prism_cripts_bridge PROPERTIES ENABLE_EXPORTS ON)
    target_link_libraries(
      test_prism_cripts_bridge
      PRIVATE ${CMAKE_DL_LIBS}
              Catch2::Catch2
              tsapi_objects
              ts::tscore
              ts::overridable_txn_vars
              ts::tsutil
              ts::http
              ts::http_remap
              ts::http2
              ts::logging
              ts::hdrs
              ts::diagsconfig
              ts::inkutils
              ts::inkdns
              ts::inkhostdb
              ts::inkcache
              ts::aio
              ts::proxy
              ts::inknet
              ts::records
              ts::inkevent
              libswoc::libswoc
              ts::jsonrpc_protocol
              ts::jsonrpc_server
              ts::rpcpublichandlers
              ts::configmanager
    )
    add_catch2_test(NAME test_prism_cripts_bridge COMMAND test_prism_cripts_bridge)
  endif()
endif()
