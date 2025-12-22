FROM docker.apple.com/edge/trafficserver-builder:latest AS build

ARG BASE=/opt/bazinga
ARG ATS_VERSION=master

RUN git clone --depth 1 -b ${ATS_VERSION} https://github.pie.apple.com/ats/trafficserver.git \
 && cmake \
     -Strafficserver \
     -Bbuild \
     -GNinja \
     -DCMAKE_INSTALL_PREFIX=${BASE} \
     -DCMAKE_BUILD_TYPE=ReleaseWithDebInfo \
     -DCMAKE_INSTALL_LIBDIR=lib/trafficserver \
     -DCMAKE_INSTALL_LIBEXECDIR=lib/trafficserver/plugins \
     -DCMAKE_INSTALL_LOGDIR=/var/log/trafficserver \
     -DCMAKE_INSTALL_CACHEDIR=/var/cache/trafficserver \
     -DCMAKE_INSTALL_RUNSTATEDIR=/var/run/trafficserver \
     -DBUILD_TESTING=OFF \
     -DBUILD_REGRESSION_TESTING=OFF \
     -DENABLE_AUTEST=OFF \
     -DBUILD_EXPERIMENTAL_PLUGINS=ON \
     -DENABLE_JEMALLOC=ON \
     -DENABLE_MALLOC_ALLOCATOR=ON \
     -DENABLE_ALLOCATOR_METRICS=ON \
     -DENABLE_CRIPTS=ON \
     -DENABLE_EXAMPLE=OFF \
     -DENABLE_LUAJIT=ON \
     -DOPENSSL_ROOT_DIR=${BASE}/boringssl \
     -DWITH_USER=bazinga \
     -DBUILD_NUMBER=${ATS_VERSION} \
 && cmake --build build \
 && cmake --install build \
 && rm -rf build trafficserver

RUN git clone --depth 1 -b ${ATS_VERSION} https://github.pie.apple.com/ats/plugins.git \
 && cmake \
     -Splugins \
     -Bbuild \
     -GNinja \
     -DCMAKE_INSTALL_PREFIX=${BASE} \
     -DCMAKE_BUILD_TYPE=ReleaseWithDebInfo \
     -DCMAKE_INSTALL_LIBDIR=lib/trafficserver \
     -DCMAKE_INSTALL_LIBEXECDIR=lib/trafficserver/plugins \
     -DCMAKE_INSTALL_LOGDIR=/var/log/trafficserver \
     -DCMAKE_INSTALL_CACHEDIR=/var/cache/trafficserver \
     -DCMAKE_INSTALL_RUNSTATEDIR=/var/run/trafficserver \
     -DBUILD_TESTING=OFF \
     -Dtsapi_ROOT=${BASE} \
     -DOPENSSL_ROOT_DIR=${BASE}/boringssl \
 && cmake --build build \
 && cmake --install build \
 && rm -rf build plugins

FROM docker.apple.com/base-images/ubi9-minimal/swift6.2-runtime

USER root

RUN groupadd bazinga && \
    adduser bazinga -g bazinga && \
    microdnf --enablerepo=epel-9 -y --setopt=tsflags=nodocs install \
      jemalloc \
      liburing \
      fmt \
      luajit \
      pcre \
      pcre2 \
      zlib \
      xz \
      hwloc \
      libcap \
      ncurses \
      libpsl && \
      microdnf clean all

COPY --from=build /opt /opt
RUN mkdir -p /var/run/trafficserver /var/log/trafficserver /var/cache/trafficserver
RUN chown bazinga /var/run/trafficserver /var/log/trafficserver /var/cache/trafficserver
ENV PATH="$PATH:/opt/bazinga/bin"

USER bazinga

EXPOSE 8080

CMD ["traffic_server"]

