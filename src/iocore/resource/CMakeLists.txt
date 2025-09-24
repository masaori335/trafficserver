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

add_library(resource STATIC Resource.cc ResourceConfig.cc ResourceConstraints.cc ResourceManager.cc ResourceStats.cc)
add_library(ts::resource ALIAS resource)

target_link_libraries(
  resource
  PUBLIC ts::tscore
  PRIVATE ts::tsutil libswoc::libswoc
)

if(BUILD_TESTING)
  add_executable(test_scenario unit_tests/test_scenario.cc)
  target_link_libraries(test_scenario PRIVATE resource Catch2::Catch2WithMain libswoc::libswoc ts::tsutil)
  add_test(
    NAME test_scenario
    COMMAND test_scenario
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/src/iocore/resource
  )

  add_executable(test_ReactiveTokenBucket unit_tests/test_ReactiveTokenBucket.cc)
  target_link_libraries(test_ReactiveTokenBucket PRIVATE resource Catch2::Catch2WithMain libswoc::libswoc ts::tsutil)
  add_test(NAME test_ReactiveTokenBucket COMMAND test_ReactiveTokenBucket)
endif()
