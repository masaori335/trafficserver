# Makefile.am for Resource Constraints
#
#  Licensed to the Apache Software Foundation (ASF) under one
#  or more contributor license agreements.  See the NOTICE file
#  distributed with this work for additional information
#  regarding copyright ownership.  The ASF licenses this file
#  to you under the Apache License, Version 2.0 (the
#  "License"); you may not use this file except in compliance
#  with the License.  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

include $(top_srcdir)/build/tidy.mk

#
# libresource
#
AM_CPPFLAGS += \
	$(iocore_include_dirs) \
	-I$(abs_top_srcdir)/include \
	-I$(abs_top_srcdir)/lib \
	-I$(abs_top_srcdir)/mgmt \
	-I$(abs_top_srcdir)/mgmt/utils \
	-I$(abs_top_srcdir)/proxy \
	-I$(abs_top_srcdir)/proxy/hdrs \
	$(TS_INCLUDES) \
	@OPENSSL_INCLUDES@ \
	@YAMLCPP_INCLUDES@

AM_LDFLAGS += \
	$(top_builddir)/src/tscore/libtscore.la \
	$(top_builddir)/src/tscpp/util/libtscpputil.la

noinst_LIBRARIES = libresource.a

libresource_a_SOURCES = \
	Resource.cc \
	ResourceConfig.cc \
	ResourceStats.cc \
	ResourceManager.cc \
	ResourceConstraints.cc

#
# unit tests
#
TESTS = test_libresource test_test_scenario

check_PROGRAMS = test_libresource test_scenario

test_libresource_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	-I$(abs_top_srcdir)/tests/include

test_libresource_LDFLAGS = \
	$(AM_LDFLAGS) \
	@OPENSSL_LDFLAGS@ \
	@YAMLCPP_LDFLAGS@

# test_libresource_LDADD = \
# 	libresource.a

test_libresource_SOURCES = \
	unit_tests/test_ReactiveTokenBucket.cc

#
# Test Tools
#
test_scenario_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	-I$(abs_top_srcdir)/tests/include

test_scenario_LDFLAGS = \
	$(AM_LDFLAGS) \
	@OPENSSL_LDFLAGS@ \
	@YAMLCPP_LDFLAGS@

# test_rtb_LDADD = \
# 	libresource.a

test_scenario_SOURCES = \
	unit_tests/test_scenario.cc
