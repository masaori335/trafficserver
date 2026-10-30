#!/bin/sh

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

##############################################################################
# This is an example compiler script for compiling Cripts and other plugins
# on the fly. You would set proxy.config.plugin.compiler_path to point to a
# customized version of this script, and it will be called whenever a plugin
# needs to be compiled via remap.config.
##############################################################################

# Configurable parts
: ${ATS_ROOT:="/tmp/ats"}

if [[ "$(uname)" == "Darwin" ]]; then
    : ${CXX:="clang++"}
    : ${CXXFLAGS:="-x c++ -std=c++20 -I/opt/homebrew/include -undefined dynamic_lookup"}
else
    CXX="/opt/bazinga/bin/clang++ -fuse-ld=lld --ld-path=/opt/bazinga/bin/ld.lld"
    # Installed headers, fmt among them, are system headers so that -Werror
    # applies to the script and not to warnings newer compilers find in them.
    CXXFLAGS="-DNDEBUG -L/opt/bazinga/lib64 -x c++ -std=c++20 -O3 -shared -fPIE -fstack-protector -fno-omit-frame-pointer -flto=thin -stdlib=libc++ -fPIC -Wall -Werror -g -gdwarf-4 -isystem ${ATS_ROOT}/include -isystem /opt/bazinga/boringssl/include -L${ATS_ROOT}/lib/trafficserver -lcripts"
    LDFLAGS="-Wl,-z,relro -Wl,-z,now -L/opt/bazinga/lib64 -Wl,-rpath,/opt/bazinga/boringssl/lib64 -Wl,-rpath,/opt/bazinga/lib64 -stdlib=libc++ -L/opt/bazinga/lib/trafficserver -Wl,-rpath,/opt/bazinga/lib/trafficserver -Wl,--build-id=sha1"
fi

# Cripts must compile against the OpenSSL headers ATS was built with, since some libcripts
# signatures follow them. Searched before CXXFLAGS, which may hold another OpenSSL.
: ${OPENSSL_INCLUDE_DIR:=""}

# Probably don't need to change these ?
STDFLAGS="-shared -fPIC -Wall -Werror -I${ATS_ROOT}/include -L${ATS_ROOT}/lib -lcripts"

# This is optional, but if set, the script will cache the compiled shared objects for faster restarts/reloads
: ${CACHE_DIR:="/tmp/ats-cache"}

# Extract the arguments, and do some sanity checks
SOURCE="$1"
DEST="$2"

SOURCE_DIR=$(dirname "$SOURCE")
DEST_DIR=$(dirname "$DEST")
SOURCE_FILE=$(basename "$SOURCE")
DEST_FILE=$(basename "$DEST")

cd "$SOURCE_DIR"
if [ $(pwd) != "$SOURCE_DIR" ]; then
    echo "Failed to cd to $SOURCE_DIR"
    exit 1
fi

cd "$DEST_DIR"
if [ $(pwd) != "$DEST_DIR" ]; then
    echo "Failed to cd to $DEST_DIR"
    exit 1
fi

if [ ! -f "$SOURCE" ]; then
    echo "Source file $SOURCE does not exist"
    exit 1
fi

if [ "${DEST_FILE}" != "${SOURCE_FILE}.so" ]; then
    echo "Destination file name must match source file name with .so extension"
    exit 1
fi

cache_file=""
if [ -d "$CACHE_DIR" ]; then
    cache_tree="${CACHE_DIR}${SOURCE_DIR}"
    cache_file="${cache_tree}/${DEST_FILE}"

    [ -d "$cache_tree" ] || mkdir -p "$cache_tree"

    if [ "$SOURCE" -ot "$cache_file" ]; then
        cp "$cache_file" "$DEST"
        exit 0
    fi

    DEST="$cache_file"
fi

# Compile the plugin
${CXX} -v ${OPENSSL_INCLUDE_DIR:+"-I${OPENSSL_INCLUDE_DIR}"} ${CXXFLAGS} ${LDFLAGS} -o "$DEST" "$SOURCE"
exit_code=$?

if [ "$exit_code" -ne 0 ]; then
    echo "Compilation failed with exit code $exit_code"
    exit $exit_code
fi

# In case we compiled to the cache, copy from the cache to the runtime destination
if [ -f "$cache_file" ]; then
    cp "$cache_file" "${DEST_DIR}/${DEST_FILE}"
fi

exit 0
