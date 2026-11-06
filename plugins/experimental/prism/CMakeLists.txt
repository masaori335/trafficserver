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
add_library(prism_ir STATIC src/ir.cc src/txn_memory.cc)
set_target_properties(prism_ir PROPERTIES POSITION_INDEPENDENT_CODE TRUE)
target_include_directories(prism_ir PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(prism_ir PUBLIC ts::tsutil)

# Installed so an extension can be built outside this tree.
install(FILES include/hrw4u/extension.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/hrw4u)

if(BUILD_TESTING)
  add_executable(test_prism_txn_memory unit_tests/test_txn_memory.cc)
  target_link_libraries(test_prism_txn_memory PRIVATE prism_ir Catch2::Catch2WithMain)
  add_catch2_test(NAME test_prism_txn_memory COMMAND test_prism_txn_memory)
endif()
