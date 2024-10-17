FROM ubuntu:24.04

# Install necessary system packages
RUN apt-get update && apt-get install -yq make \
    git \
    cmake \
    m4 \
    g++ \
    flex \
    bison \
    libgflags-dev \
    libgoogle-glog-dev \
    libkrb5-dev \
    libsasl2-dev \
    libnuma-dev \
    pkg-config \
    libssl-dev \
    libcap-dev \
    gperf \
    libevent-dev \
    libtool \
    libboost-all-dev \
    libjemalloc-dev \
    libsnappy-dev \
    wget \
    unzip \
    libiberty-dev \
    liblz4-dev \
    liblzma-dev \
    make \
    zlib1g-dev \
    binutils-dev \
    libsodium-dev \
    libdouble-conversion-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Build proxygen
RUN git clone https://github.com/facebook/proxygen.git \
    && cd /proxygen \
    && git checkout tags/v2024.08.12.00 \
    && ./getdeps.sh --no-tests

RUN ldd /tmp/fbcode_builder_getdeps-ZproxygenZbuildZfbcode_builder-root/build/proxygen/proxygen/httpserver/hq | grep "=> /" | awk '{print $3}' > libs.txt
RUN tar cvf libs.tar --dereference --files-from=libs.txt

FROM ubuntu:24.04

# Copy HQ
COPY --from=0 /tmp/fbcode_builder_getdeps-ZproxygenZbuildZfbcode_builder-root/build/proxygen/proxygen/httpserver/hq /proxygen/_build/proxygen/bin/hq
# Copy shared libs
COPY --from=0 libs.tar /
RUN tar xvf libs.tar
RUN rm libs.tar

# Set the working directory
WORKDIR /proxygen/proxygen

# Copy the necessary files
RUN mkdir -p root
COPY index.html root/index.html
COPY index.html root/test.html
COPY largeFile.html root/largeFile.html
COPY launch_server.sh .
COPY ssl_cert.pem .
COPY ssl_key.pem .

# Make the shell script executable
RUN chmod +x launch_server.sh


# Set the entrypoint to launch the server
ENTRYPOINT ["./launch_server.sh"]